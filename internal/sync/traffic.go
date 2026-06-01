package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/models"
	"gorm.io/gorm"
)

var (
	// userTrafficMap stores UID -> [Upload, Download] (Deltas for V2Board sync)
	userTrafficMap sync.Map
	// totalTrafficMap stores Tag/UserEmail -> [TotalUpload, TotalDownload] (Lifetime stats for UI)
	totalTrafficMap sync.Map
	// activeUsers stores UserEmail (Tag) -> LastSeenTime
	activeUsers sync.Map
	// nodeStatsMap stores NodeID -> *models.SystemStats
	nodeStatsMap sync.Map
	// persistTicker 定时持久化流量到数据库
	persistTicker *time.Ticker

	// syncedEntryTraffic 记录上次持久化时入口节点的内存流量值，用于计算增量
	syncedEntryTraffic = make(map[uint][2]int64)
	syncedEntryLock    sync.RWMutex

	// syncedExitTraffic 记录上次持久化时落地节点的内存流量值，用于计算增量
	syncedExitTraffic = make(map[uint][2]int64)
	syncedExitLock    sync.RWMutex
)

// InitTrafficFromDB 从数据库加载历史流量统计
func InitTrafficFromDB() {
	log.Println("[Traffic] Loading traffic stats from database...")

	// 0. 数据清洗：将历史数据的 NULL 字段初始化为 0
	// 这里的 SQL 是为了防止 "NULL + delta = NULL" 导致增量更新失效，这是流量"永远很少"的根本原因
	database.DB.Exec("UPDATE entry_nodes SET total_upload = 0 WHERE total_upload IS NULL")
	database.DB.Exec("UPDATE entry_nodes SET total_download = 0 WHERE total_download IS NULL")
	database.DB.Exec("UPDATE exit_nodes SET total_upload = 0 WHERE total_upload IS NULL")
	database.DB.Exec("UPDATE exit_nodes SET total_download = 0 WHERE total_download IS NULL")

	// 仅打印日志，不需要将 DB 数据加载回内存，因为我们将采用 DB + (Mem - Synced) 的显示策略
	var entries []models.EntryNode
	database.DB.Find(&entries)
	for _, entry := range entries {
		if entry.TotalUpload > 0 || entry.TotalDownload > 0 {
			log.Printf("[Traffic] Entry #%d persistent: ↑%s ↓%s", entry.ID, formatBytes(entry.TotalUpload), formatBytes(entry.TotalDownload))
		}
	}

	// 启动定时持久化任务 (每 5 分钟)
	persistTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for range persistTicker.C {
			PersistTrafficToDB()
		}
	}()

	log.Println("[Traffic] Traffic persistence initialized (interval: 5min)")
}

// CollectTraffic 接收来自 Agent 的流量快照
func CollectTraffic(report models.NodeTrafficReport) {
	for _, t := range report.Traffic {
		// 精确匹配：必须是这个入口下的这个特定标签 (例如 n21-ed296cba)
		var rule models.ForwardingRule
		err := database.DB.Where("user_email = ? AND entry_node_id = ?", t.UserEmail, report.NodeID).First(&rule).Error
		if err != nil {
			// 兜底：如果完全匹配失败，尝试去掉前缀匹配 UUID (兼容旧版或特殊标签)
			lookupUUID := t.UserEmail
			if parts := strings.Split(t.UserEmail, "-"); len(parts) > 1 {
				lookupUUID = parts[len(parts)-1]
			}
			err = database.DB.Where("user_id = ? AND entry_node_id = ?", lookupUUID, report.NodeID).First(&rule).Error
			if err != nil {
				log.Printf("[Traffic] 无法定位用户规则: %s (Entry #%d)", t.UserEmail, report.NodeID)
				continue
			}
		}

		if rule.V2boardUID == 0 {
			continue
		}

		// 记录在线状态 (使用 Tag 而不是 UID，以便区分不同节点的在线状态)
		activeUsers.Store(rule.UserEmail, time.Now())

		// 累加流量 (增量)
		if t.Upload > 0 || t.Download > 0 {
			// 1. 记录增量 (用于 V2Board 同步, 同步后清零)
			val, _ := userTrafficMap.LoadOrStore(t.UserEmail, &[2]int64{0, 0})
			traffic := val.(*[2]int64)
			atomic.AddInt64(&traffic[0], t.Upload)
			atomic.AddInt64(&traffic[1], t.Download)

			// 2. 记录总量 (用于 UI 展示, 不清零)
			totVal, _ := totalTrafficMap.LoadOrStore(t.UserEmail, &[2]int64{0, 0})
			totalTraffic := totVal.(*[2]int64)
			atomic.AddInt64(&totalTraffic[0], t.Upload)
			atomic.AddInt64(&totalTraffic[1], t.Download)
			// log.Printf("[Debug] 收到用户 %s (UID %d) 流量: Up %d, Down %d", t.UserEmail, rule.V2boardUID, t.Upload, t.Download)
		}
	}
	// log.Printf("[Traffic] 收到 Agent 流量汇报: Node %d, 条目数 %d", report.NodeID, len(report.Traffic))

	// 记录系统探针数据
	if report.Stats != nil {
		report.Stats.ReportAt = time.Now().Unix()

		targetID := report.NodeID
		found := false

		// 调试日志：看看原始上报的是什么
		// log.Printf("[Traffic-Debug] 原始上报 NodeID: %d", report.NodeID)

		// 1. 尝试直接匹配入口 ID
		var entry models.EntryNode
		if err := database.DB.First(&entry, targetID).Error; err == nil {
			found = true
		} else {
			// 2. 尝试匹配入口节点的 v2board_node_id
			if err := database.DB.Where("v2board_node_id = ?", targetID).First(&entry).Error; err == nil {
				targetID = entry.ID
				found = true
			} else {
				// 3. 尝试从多端口映射表中找
				var mapping models.NodeMapping
				if err := database.DB.Where("v2board_node_id = ?", targetID).First(&mapping).Error; err == nil {
					targetID = mapping.EntryNodeID
					found = true
				}
			}
		}

		if found {
			nodeStatsMap.Store(targetID, report.Stats)
			// 探针正常映射完全静默，不再打印
		} else {
			// 极端情况：完全不认识此 ID，但我们依然存下来，Key 使用上报的原始 ID
			nodeStatsMap.Store(targetID, report.Stats)
			log.Printf("[Traffic-Warning] 收到未知节点的探针数据: ID #%d (请检查 Agent 启动参数)", targetID)
		}
	}
}

// StartTrafficReporting 启动心跳和上报任务
func StartTrafficReporting() {
	// 流量与人数合一上报，每 1 分钟执行一次 (配合 V2Board 默认缓存时间)
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			pushTrafficAndOnlineToV2Board()
		}
	}()
}

func pushTrafficAndOnlineToV2Board() {
	var defaultSource models.EntryNode
	err := database.DB.Where("v2board_url <> '' AND v2board_key <> ''").First(&defaultSource).Error
	if err != nil {
		return
	}

	var entries []models.EntryNode
	database.DB.Find(&entries)

	now := time.Now()
	for _, entry := range entries {
		if entry.V2boardURL == "" || entry.V2boardKey == "" {
			entry.V2boardURL = defaultSource.V2boardURL
			entry.V2boardKey = defaultSource.V2boardKey
		}
		// 按 V2Board Node ID 分组的 Payloads
		nodePayloads := make(map[int]map[string][]int64)

		// 事务回滚数据结构：NodeID -> []{UserEmail, Up, Down}
		// 如果上报失败，我们需要知道把流量退还给谁
		type trafficTx struct {
			UserEmail string
			Up        int64
			Down      int64
		}
		rollbackData := make(map[int][]trafficTx)

		var rules []models.ForwardingRule
		database.DB.Where("entry_node_id = ?", entry.ID).Find(&rules)

		for _, rule := range rules {
			uid := rule.V2boardUID
			if uid == 0 {
				continue
			}

			// 从 UserEmail (标签) 中提取真正的 V2Board 节点 ID
			// 格式: n20-ed296cba
			reportingNodeID := entry.V2boardNodeID // 默认值
			if strings.HasPrefix(rule.UserEmail, "n") && strings.Contains(rule.UserEmail, "-") {
				idPart := strings.Split(rule.UserEmail, "-")[0][1:] // 拿到 "20"
				if id, err := strconv.Atoi(idPart); err == nil {
					reportingNodeID = id
				}
			}

			// 初始化该节点的 PayloadMap
			if _, ok := nodePayloads[reportingNodeID]; !ok {
				nodePayloads[reportingNodeID] = make(map[string][]int64)
			}

			// 获取流量增量 (使用 UserEmail 作为 Key)
			var u, d int64
			if val, ok := userTrafficMap.Load(rule.UserEmail); ok {
				traffic := val.(*[2]int64)
				u = atomic.SwapInt64(&traffic[0], 0)
				d = atomic.SwapInt64(&traffic[1], 0)
			}

			// 如果有流量被取出，立即记录到回滚日志，以防发送失败
			if u > 0 || d > 0 {
				rollbackData[reportingNodeID] = append(rollbackData[reportingNodeID], trafficTx{
					UserEmail: rule.UserEmail,
					Up:        u,
					Down:      d,
				})
			}

			// 判断是否在线
			isOnline := false
			// 使用 rule.UserEmail (Tag) 检查在线状态，实现分节点在线统计
			if lastSeen, ok := activeUsers.Load(rule.UserEmail); ok {
				if now.Sub(lastSeen.(time.Time)) < 3*time.Minute {
					isOnline = true
				} else {
					activeUsers.Delete(rule.UserEmail)
				}
			}

			if isOnline || u > 0 || d > 0 {
				nodePayloads[reportingNodeID][fmt.Sprintf("%d", uid)] = []int64{u, d}
			}
		}

		// 确保 Entry 默认节点和 Mapping 节点都有心跳
		var mappings []models.NodeMapping
		database.DB.Where("entry_node_id = ?", entry.ID).Find(&mappings)

		allTargetNodeIDs := make(map[int]bool)
		if entry.V2boardNodeID != 0 {
			allTargetNodeIDs[entry.V2boardNodeID] = true
		}
		for _, m := range mappings {
			allTargetNodeIDs[m.V2boardNodeID] = true
		}
		for nodeID := range nodePayloads {
			allTargetNodeIDs[nodeID] = true
		}

		for nodeID := range allTargetNodeIDs {
			payload := nodePayloads[nodeID]
			if payload == nil {
				payload = make(map[string][]int64)
			}

			nodeType := entry.V2boardType
			for _, m := range mappings {
				if m.V2boardNodeID == nodeID && m.V2boardType != "" {
					nodeType = m.V2boardType
					break
				}
			}
			if nodeType == "" {
				nodeType = "v2ray"
			}
			// V2Board 已原生支持 AnyTLS，无需再合并到 VLESS

			var totalUp, totalDown int64
			for _, v := range payload {
				totalUp += v[0]
				totalDown += v[1]
			}

			err := reportToV2BoardAPIWithID(entry, nodeID, nodeType, payload)
			if err != nil {
				log.Printf("[Sync-Error] V2Board 同步失败 (Entry #%d, Node #%d): %v. 正在执行流量回滚...", entry.ID, nodeID, err)

				// --- 核心修复：执行流量回滚 ---
				if txList, ok := rollbackData[nodeID]; ok {
					restoredCount := 0
					for _, tx := range txList {
						// 将流量原子加回 map
						val, _ := userTrafficMap.LoadOrStore(tx.UserEmail, &[2]int64{0, 0})
						traffic := val.(*[2]int64)
						atomic.AddInt64(&traffic[0], tx.Up)
						atomic.AddInt64(&traffic[1], tx.Down)
						restoredCount++
					}
					log.Printf("[Sync-Rollback] 已成功回滚 %d 个用户的流量数据，等待下一次重试。", restoredCount)
				}
				// ---------------------------
			} else {
				// 详尽保留流量日志，方便监控
				status := "OK"
				if totalUp+totalDown == 0 {
					status = "EMPTY" // 高亮显示无流量上报，方便发现断流
				}
				log.Printf("[Sync] [%s] Entry #%d -> V2B Node #%d: %d 用户, ↑ %s, ↓ %s",
					status, entry.ID, nodeID, len(payload), formatBytes(totalUp), formatBytes(totalDown))
			}
		}
	}
}

func reportToV2BoardAPIWithID(entry models.EntryNode, nodeID int, nodeType string, importData map[string][]int64) error {
	apiURL := entry.V2boardURL
	if len(apiURL) > 0 && apiURL[len(apiURL)-1] == '/' {
		apiURL = apiURL[:len(apiURL)-1]
	}

	fullURL := fmt.Sprintf("%s/api/v1/server/UniProxy/push?token=%s&node_id=%d&node_type=%s",
		apiURL, entry.V2boardKey, nodeID, nodeType)

	jsonData, _ := json.Marshal(importData)
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post(fullURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// GetTrafficStats 返回所有标签的流量总计 map[UserEmail]TrafficStats
func GetTrafficStats() map[string]models.TrafficStat {
	stats := make(map[string]models.TrafficStat)
	totalTrafficMap.Range(func(key, value interface{}) bool {
		userEmail := key.(string)
		counters := value.(*[2]int64)
		stats[userEmail] = models.TrafficStat{
			Upload:   atomic.LoadInt64(&counters[0]),
			Download: atomic.LoadInt64(&counters[1]),
		}
		return true
	})
	return stats
}

// EntryTrafficStats 入口节点流量统计响应结构
type EntryTrafficStats struct {
	EntryStats map[uint]models.TrafficStat   `json:"entry_stats"` // entry_id -> traffic
	ExitStats  map[uint]models.TrafficStat   `json:"exit_stats"`  // exit_id -> traffic
	UserStats  map[string]models.TrafficStat `json:"user_stats"`  // user_email -> traffic
	NodeStats  map[uint]*models.SystemStats  `json:"node_stats"`  // node_id -> system stats
}

// GetTrafficStatsByEntry 返回按入口节点聚合的流量统计
func GetTrafficStatsByEntry() EntryTrafficStats {
	result := EntryTrafficStats{
		EntryStats: make(map[uint]models.TrafficStat),
		ExitStats:  make(map[uint]models.TrafficStat),
		UserStats:  make(map[string]models.TrafficStat),
		NodeStats:  make(map[uint]*models.SystemStats),
	}

	// 获取所有探针数据
	nodeStatsMap.Range(func(key, value interface{}) bool {
		result.NodeStats[key.(uint)] = value.(*models.SystemStats)
		return true
	})

	// 获取所有用户流量 (内存中的实时数据)
	userStats := GetTrafficStats()
	result.UserStats = userStats

	// 从数据库读取持久化的入口节点流量
	var entries []models.EntryNode
	database.DB.Find(&entries)
	for _, entry := range entries {
		dbUp := entry.TotalUpload
		dbDown := entry.TotalDownload

		// 计算内存中的当前值
		var memUp, memDown int64
		// 获取该节点下所有用户的实时流量总和
		// 优化：这里遍历所有规则可能较慢，但对于一般规模(几千用户)是可以接受的
		// 如果规模很大，应该在 collect 时维护 node 维度的缓存
		var rules []models.ForwardingRule
		database.DB.Where("entry_node_id = ?", entry.ID).Find(&rules)
		for _, rule := range rules {
			if stat, ok := userStats[rule.UserEmail]; ok {
				memUp += stat.Upload
				memDown += stat.Download
			}
		}

		// 获取上次同步时的值 (Offset)
		syncedEntryLock.RLock()
		synced := syncedEntryTraffic[entry.ID]
		syncedEntryLock.RUnlock()

		// 核心公式: 显示值 = 数据库持久化值 + (内存当前值 - 上次同步值)
		// 括号内即为"自上次持久化以来产生的新流量"
		pendingUp := memUp - synced[0]
		pendingDown := memDown - synced[1]

		// 防御性检查：理论上 pending >= 0，但如果发生内存重置等异常，取 0
		if pendingUp < 0 {
			pendingUp = 0
		}
		if pendingDown < 0 {
			pendingDown = 0
		}

		finalUp := dbUp + pendingUp
		finalDown := dbDown + pendingDown

		if finalUp > 0 || finalDown > 0 {
			result.EntryStats[entry.ID] = models.TrafficStat{
				Upload:   finalUp,
				Download: finalDown,
			}
		}
	}

	// 从数据库读取持久化的落地节点流量
	var exits []models.ExitNode
	database.DB.Find(&exits)
	for _, exit := range exits {
		dbUp := exit.TotalUpload
		dbDown := exit.TotalDownload

		var memUp, memDown int64
		var rules []models.ForwardingRule
		database.DB.Where("exit_node_id = ?", exit.ID).Find(&rules)
		for _, rule := range rules {
			if stat, ok := userStats[rule.UserEmail]; ok {
				memUp += stat.Upload
				memDown += stat.Download
			}
		}

		syncedExitLock.RLock()
		synced := syncedExitTraffic[exit.ID]
		syncedExitLock.RUnlock()

		pendingUp := memUp - synced[0]
		pendingDown := memDown - synced[1]

		if pendingUp < 0 {
			pendingUp = 0
		}
		if pendingDown < 0 {
			pendingDown = 0
		}

		finalUp := dbUp + pendingUp
		finalDown := dbDown + pendingDown

		if finalUp > 0 || finalDown > 0 {
			result.ExitStats[exit.ID] = models.TrafficStat{
				Upload:   finalUp,
				Download: finalDown,
			}
		}
	}

	return result
}

// PersistTrafficToDB 将内存中的流量统计增量持久化到数据库
func PersistTrafficToDB() {
	// 获取当前内存中的用户流量统计
	userStats := GetTrafficStats()

	// 遍历所有转发规则，聚合节点当前的内存总量
	var rules []models.ForwardingRule
	database.DB.Find(&rules)

	entryCur := make(map[uint][2]int64)
	exitCur := make(map[uint][2]int64)

	for _, rule := range rules {
		if stat, ok := userStats[rule.UserEmail]; ok {
			entryCur[rule.EntryNodeID] = [2]int64{
				entryCur[rule.EntryNodeID][0] + stat.Upload,
				entryCur[rule.EntryNodeID][1] + stat.Download,
			}
			exitCur[rule.ExitNodeID] = [2]int64{
				exitCur[rule.ExitNodeID][0] + stat.Upload,
				exitCur[rule.ExitNodeID][1] + stat.Download,
			}
		}
	}

	// 更新入口节点流量 (原子增量更新)
	syncedEntryLock.Lock()
	for entryID, current := range entryCur {
		synced := syncedEntryTraffic[entryID]
		deltaUp := current[0] - synced[0]
		deltaDown := current[1] - synced[1]

		if deltaUp > 0 || deltaDown > 0 {
			// 执行 SQL 增量更新
			if err := database.DB.Model(&models.EntryNode{}).Where("id = ?", entryID).
				Updates(map[string]interface{}{
					"total_upload":   gorm.Expr("total_upload + ?", deltaUp),
					"total_download": gorm.Expr("total_download + ?", deltaDown),
				}).Error; err == nil {
				// 更新成功后，更新已同步标记
				syncedEntryTraffic[entryID] = current
			} else {
				log.Printf("[Traffic] Failed to persist entry #%d: %v", entryID, err)
			}
		} else {
			// 即使没有增量，也要更新 synced 游标(如果 synced 落后于 current 的话)
			// 但这里 delta <= 0 说明没有新流量或者 reset 过，直接对齐即可
			syncedEntryTraffic[entryID] = current
		}
	}
	syncedEntryLock.Unlock()

	// 更新落地节点流量
	syncedExitLock.Lock()
	for exitID, current := range exitCur {
		synced := syncedExitTraffic[exitID]
		deltaUp := current[0] - synced[0]
		deltaDown := current[1] - synced[1]

		if deltaUp > 0 || deltaDown > 0 {
			if err := database.DB.Model(&models.ExitNode{}).Where("id = ?", exitID).
				Updates(map[string]interface{}{
					"total_upload":   gorm.Expr("total_upload + ?", deltaUp),
					"total_download": gorm.Expr("total_download + ?", deltaDown),
				}).Error; err == nil {
				syncedExitTraffic[exitID] = current
			} else {
				log.Printf("[Traffic] Failed to persist exit #%d: %v", exitID, err)
			}
		} else {
			syncedExitTraffic[exitID] = current
		}
	}
	syncedExitLock.Unlock()

	log.Printf("[Traffic] Persisted traffic to database: %d entries, %d exits", len(entryCur), len(exitCur))
}

// ClearEntryTraffic 清除指定入口节点的流量
func ClearEntryTraffic(entryID uint) error {
	// 1. 清空数据库字段
	if err := database.DB.Model(&models.EntryNode{}).Where("id = ?", entryID).
		Updates(map[string]interface{}{
			"total_upload":   0,
			"total_download": 0,
		}).Error; err != nil {
		return err
	}

	// 2. 重置同步游标，使其等于当前内存值
	syncedEntryLock.Lock()
	defer syncedEntryLock.Unlock()

	// 计算当前 Memory 值
	userStats := GetTrafficStats()
	var curUp, curDown int64
	var rules []models.ForwardingRule
	database.DB.Where("entry_node_id = ?", entryID).Find(&rules)
	for _, rule := range rules {
		if stat, ok := userStats[rule.UserEmail]; ok {
			curUp += stat.Upload
			curDown += stat.Download
		}
	}
	syncedEntryTraffic[entryID] = [2]int64{curUp, curDown}

	log.Printf("[Traffic] Cleared traffic for Entry #%d (synced to mem: %d/%d)", entryID, curUp, curDown)
	return nil
}

// ClearExitTraffic 清除指定落地节点的流量
func ClearExitTraffic(exitID uint) error {
	if err := database.DB.Model(&models.ExitNode{}).Where("id = ?", exitID).
		Updates(map[string]interface{}{
			"total_upload":   0,
			"total_download": 0,
		}).Error; err != nil {
		return err
	}

	syncedExitLock.Lock()
	defer syncedExitLock.Unlock()

	userStats := GetTrafficStats()
	var curUp, curDown int64
	var rules []models.ForwardingRule
	database.DB.Where("exit_node_id = ?", exitID).Find(&rules)
	for _, rule := range rules {
		if stat, ok := userStats[rule.UserEmail]; ok {
			curUp += stat.Upload
			curDown += stat.Download
		}
	}

	syncedExitTraffic[exitID] = [2]int64{curUp, curDown}

	log.Printf("[Traffic] Cleared traffic for Exit #%d", exitID)
	return nil
}

func ClearAllTraffic() error {
	// 简单的实现：全部清零 DB
	database.DB.Model(&models.EntryNode{}).Where("1=1").Updates(map[string]interface{}{"total_upload": 0, "total_download": 0})
	database.DB.Model(&models.ExitNode{}).Where("1=1").Updates(map[string]interface{}{"total_upload": 0, "total_download": 0})

	// 重置所有 Synced 指针到当前 Memory 值
	PersistTrafficToDB() // 利用 Persist 重新对齐 SyncedMap

	log.Println("[Traffic] Cleared ALL traffic for all nodes")
	return nil
}
