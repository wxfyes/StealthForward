package sync

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/models"
	"gorm.io/gorm"
)

// V2boardUser 对应 UniProxy 接口返回的用户结构
type V2boardUser struct {
	ID   uint   `json:"id"`
	UUID string `json:"uuid"`
}

type V2boardResponse struct {
	Data  []V2boardUser `json:"data"`
	Users []V2boardUser `json:"users"` // 适配 V2board 源码中的 users 键
}

// StartV2boardSync 启动一个后台任务，定时同步用户列表
func StartV2boardSync() {
	ticker := time.NewTicker(2 * time.Minute) // 每 2 分钟同步一次
	go func() {
		for range ticker.C {
			syncAllNodes()
		}
	}()
	// 启动时先同步一次
	go syncAllNodes()
}

func syncAllNodes() {
	var defaultSource models.EntryNode
	err := database.DB.Where("v2board_url <> '' AND v2board_key <> ''").First(&defaultSource).Error
	if err != nil {
		log.Println("!!!! [D-Sync] 找不到任何有效的 V2Board 配置，同步取消")
		return
	}

	var entries []models.EntryNode
	database.DB.Find(&entries)

	for _, entry := range entries {
		if entry.V2boardURL == "" || entry.V2boardKey == "" {
			entry.V2boardURL = defaultSource.V2boardURL
			entry.V2boardKey = defaultSource.V2boardKey
		}
		processedUUIDs := make(map[string]bool) // 记录已由 Mapping 处理过的用户，防止被默认规则覆盖

		// 1. 先同步 Mapping 规则 (最高优先级，按 ID 降序排列，让新节点/手动节点优先夺取用户)
		var mappings []models.NodeMapping
		database.DB.Where("entry_node_id = ?", entry.ID).Order("id DESC").Find(&mappings)

		var activeUUIDs []string
		for _, m := range mappings {
			log.Printf(">>>> [D-Sync] 优先分流同步: V2B节点#%d -> 落地ID#%d", m.V2boardNodeID, m.TargetExitID)
			uuids := syncSingleTarget(entry, m.V2boardNodeID, m.V2boardType, m.TargetExitID, processedUUIDs)
			activeUUIDs = append(activeUUIDs, uuids...)
		}

		// 2. 再同步 EntryNode 自身的默认规则 (避开已被映射的用户 AND 已在 Mapping 中定义的节点)
		if entry.V2boardNodeID != 0 {
			// 检查这个 V2B Node ID 是否已经在 Mapping 中定义
			alreadyMapped := false
			for _, m := range mappings {
				if m.V2boardNodeID == entry.V2boardNodeID {
					alreadyMapped = true
					break
				}
			}
			// 如果没有被 Mapping 定义，才用默认落地同步
			if !alreadyMapped {
				nodeType := entry.V2boardType
				if nodeType == "" {
					nodeType = "v2ray"
				}
				uuids := syncSingleTarget(entry, entry.V2boardNodeID, nodeType, entry.TargetExitID, processedUUIDs)
				activeUUIDs = append(activeUUIDs, uuids...)
			}
		}

		// 3. 清理已失效/过期用户
		if len(activeUUIDs) > 0 {
			database.DB.Where("entry_node_id = ? AND user_id NOT IN ?", entry.ID, activeUUIDs).Delete(&models.ForwardingRule{})
		} else {
			database.DB.Where("entry_node_id = ?", entry.ID).Delete(&models.ForwardingRule{})
		}
	}
}

func syncSingleTarget(entry models.EntryNode, v2bNodeID int, v2bType string, targetExitID uint, processed map[string]bool) []string {
	if v2bNodeID <= 0 {
		return nil
	}
	users, err := fetchUsers(entry, v2bNodeID, v2bType)
	if err != nil {
		log.Printf("!!!! [D-Sync] 同步故障 (NodeID %d): %v", v2bNodeID, err)
		return nil
	}

	// 不再去重！每个节点的用户都需要同步，同一个 UUID 可以有多个身份（n20-xxx, n21-xxx）
	// 这样用户才能自由切换节点
	if len(users) > 0 {
		updateRulesForEntry(entry.ID, entry.Name, targetExitID, v2bNodeID, users)
	}

	uuids := make([]string, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
	}
	return uuids
}

func fetchUsers(entry models.EntryNode, nodeID int, nodeType string) ([]V2boardUser, error) {
	apiURL := entry.V2boardURL
	key := entry.V2boardKey

	if len(apiURL) > 0 && apiURL[len(apiURL)-1] == '/' {
		apiURL = apiURL[:len(apiURL)-1]
	}
	fullURL := fmt.Sprintf("%s/api/v1/server/UniProxy/user?node_id=%d&token=%s&node_type=%s", apiURL, nodeID, key, nodeType)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(fullURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("V2Board 返回错误 %d: %s", resp.StatusCode, string(body))
	}

	var v2resp V2boardResponse
	if err := json.Unmarshal(body, &v2resp); err != nil {
		var directUsers []V2boardUser
		if err2 := json.Unmarshal(body, &directUsers); err2 == nil {
			return directUsers, nil
		}
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}

	return append(v2resp.Data, v2resp.Users...), nil
}

func updateRulesForEntry(entryID uint, entryName string, targetExitID uint, v2bNodeID int, users []V2boardUser) {
	// 终极性能优化：全量预加载 + 内存比对
	// 1. 将 O(N) 次 SQL 查询降低为 O(1) 次
	// 2. 仅在字段真正变更时才产生写操作
	database.DB.Transaction(func(tx *gorm.DB) error {
		// --- Step 1: 预加载当前节点的所有规则到内存 ---
		var existingList []models.ForwardingRule
		// 只查属于当前 Entry 的规则，减少传输量
		if err := tx.Where("entry_node_id = ?", entryID).Find(&existingList).Error; err != nil {
			return err
		}

		// 构建快速查找索引: UserEmail -> Rule Pointer
		ruleMap := make(map[string]*models.ForwardingRule)
		for i := range existingList {
			// 使用指针以便直接修改
			ruleMap[existingList[i].UserEmail] = &existingList[i]
		}
		// ---------------------------------------------

		// --- Step 2: 内存比对 (无 SQL 查询) ---
		for _, user := range users {
			identityTag := fmt.Sprintf("n%d-%s", v2bNodeID, user.UUID[:8])

			// 直接从 Map 获取，不再查询数据库
			rule, exists := ruleMap[identityTag]

			if !exists {
				// Case A: 新增规则
				newRule := models.ForwardingRule{
					EntryNodeID: entryID,
					ExitNodeID:  targetExitID,
					UserID:      user.UUID,
					V2boardUID:  user.ID,
					UserEmail:   identityTag,
					Enabled:     true,
				}
				if err := tx.Create(&newRule).Error; err != nil {
					log.Printf("[Sync] Failed to create rule for %s: %v", identityTag, err)
				}
			} else {
				// Case B: 检查更新
				updated := false

				// 逐字段比对，只有真正变化才触发 Update
				if rule.V2boardUID != user.ID {
					rule.V2boardUID = user.ID
					updated = true
				}
				if rule.ExitNodeID != targetExitID {
					rule.ExitNodeID = targetExitID
					updated = true
				}
				if !rule.Enabled {
					rule.Enabled = true
					updated = true
				}
				// UserEmail (Tag) 已经在 Key 里匹配了，理论上不需要比对，但为了保险
				if rule.UserEmail != identityTag {
					rule.UserEmail = identityTag
					updated = true
				}

				if updated {
					// 只有变了才写库
					if err := tx.Save(rule).Error; err != nil {
						log.Printf("[Sync] Failed to update rule for %s: %v", identityTag, err)
					}
				}
			}
		}
		return nil
	})
}

// GlobalSyncNow 提供给 API 调用的立即同步接口
func GlobalSyncNow() {
	go syncAllNodes()
}
