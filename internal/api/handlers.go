package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wangn9900/StealthForward/internal/cloud"
	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/generator"
	"github.com/wangn9900/StealthForward/internal/models"
	"github.com/wangn9900/StealthForward/internal/sync"
	"gorm.io/gorm"
)

// GetConfigHandler 为指定的入口节点生成 Sing-box 配置
func GetConfigHandler(c *gin.Context) {
	nodeIDStr := c.Param("id")
	nodeID, err := strconv.ParseUint(nodeIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid node id"})
		return
	}

	// 1. 获取入口节点信息
	var entry models.EntryNode
	if err := database.DB.First(&entry, nodeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry node not found"})
		return
	}

	// 2. 获取该节点下的所有有效转发规则
	var rules []models.ForwardingRule
	database.DB.Where("entry_node_id = ? AND enabled = ?", nodeID, true).Find(&rules)

	// 3. 获取所有落地节点 (加载全部，确保动态分流时 outbound 标签始终存在)
	var exits []models.ExitNode
	database.DB.Find(&exits)

	// 4. 生成配置
	config, err := generator.GenerateEntryConfig(&entry, rules, exits)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate config"})
		return
	}
	// 4. 获取 CF_API_TOKEN (用于下发给 Agent 实现最稳定的 DNS-01 验证)
	var cfToken string
	var setting models.SystemSetting
	if err := database.DB.Where("key = ?", "cloudflare.api_token").First(&setting).Error; err == nil {
		cfToken = setting.Value
	}

	// 5. 返回 JSON 响应，包含配置和可能的任务
	c.JSON(http.StatusOK, gin.H{
		"config":    config,
		"cert_task": entry.CertTask,
		"domain":    entry.Domain,
		"cf_token":  cfToken,
	})
}

func RegisterNodeHandler(c *gin.Context) {
	var entry models.EntryNode
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// === 授权检查 ===
	// 检查节点数量限制
	if !CheckCanAddEntry(c) {
		return
	}
	// 检查协议权限
	if entry.Protocol != "" && !CheckProtocolAllowed(c, entry.Protocol) {
		return
	}

	database.DB.Save(&entry)
	// 保存成功后立即尝试拉取一次 V2Board 数据
	sync.GlobalSyncNow()
	c.JSON(http.StatusOK, entry)
}

// ExitNode 管理接口
func CreateExitNodeHandler(c *gin.Context) {
	var exit models.ExitNode
	if err := c.ShouldBindJSON(&exit); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// === 授权检查：落地节点数量限制 ===
	if !CheckCanAddExit(c) {
		return
	}

	// 自动从 Config JSON 中提取端口和地址并同步到字段
	if exit.Config != "" {
		var cfg map[string]interface{}
		if err := json.Unmarshal([]byte(exit.Config), &cfg); err == nil {
			// 同步端口
			if exit.Port == 0 {
				if p, ok := cfg["server_port"].(float64); ok {
					exit.Port = int(p)
				} else if p, ok := cfg["port"].(float64); ok {
					exit.Port = int(p)
				}
			}
			// 同步地址
			if exit.Address == "" {
				if s, ok := cfg["server"].(string); ok {
					exit.Address = s
				} else if a, ok := cfg["address"].(string); ok {
					exit.Address = a
				}
			}
		}
	}

	database.DB.Save(&exit)
	c.JSON(http.StatusOK, exit)
}

func ListExitNodesHandler(c *gin.Context) {
	var exits []models.ExitNode
	database.DB.Find(&exits)

	// 后端自愈逻辑：如果发现库里端口或地址缺失，自动解析并修正
	for i := range exits {
		if (exits[i].Port == 0 || exits[i].Address == "") && exits[i].Config != "" {
			var cfg map[string]interface{}
			if err := json.Unmarshal([]byte(exits[i].Config), &cfg); err == nil {
				updated := false
				// 修正端口
				if exits[i].Port == 0 {
					if p, ok := cfg["server_port"].(float64); ok {
						exits[i].Port = int(p)
						updated = true
					} else if p, ok := cfg["port"].(float64); ok {
						exits[i].Port = int(p)
						updated = true
					}
				}
				// 修正地址
				if exits[i].Address == "" {
					if s, ok := cfg["server"].(string); ok {
						exits[i].Address = s
						updated = true
					} else if a, ok := cfg["address"].(string); ok {
						exits[i].Address = a
						updated = true
					}
				}

				if updated {
					// 悄悄修正数据库，一劳永逸
					database.DB.Model(&models.ExitNode{}).Where("id = ?", exits[i].ID).Select("port", "address").Updates(map[string]interface{}{
						"port":    exits[i].Port,
						"address": exits[i].Address,
					})
				}
			}
		}
	}
	c.JSON(http.StatusOK, exits)
}

// ForwardingRule 管理接口 (分流核心)
func CreateForwardingRuleHandler(c *gin.Context) {
	var rule models.ForwardingRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 默认设为启用
	rule.Enabled = true
	database.DB.Create(&rule)
	c.JSON(http.StatusOK, rule)
}

func ListForwardingRulesHandler(c *gin.Context) {
	var rules []models.ForwardingRule
	database.DB.Find(&rules)
	c.JSON(http.StatusOK, rules)
}

func ListEntryNodesHandler(c *gin.Context) {
	var entries []models.EntryNode
	database.DB.Find(&entries)
	c.JSON(http.StatusOK, entries)
}

func DeleteEntryNodeHandler(c *gin.Context) {
	id := c.Param("id")
	database.DB.Delete(&models.EntryNode{}, id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func DeleteExitNodeHandler(c *gin.Context) {
	id := c.Param("id")
	database.DB.Delete(&models.ExitNode{}, id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func DeleteForwardingRuleHandler(c *gin.Context) {
	id := c.Param("id")
	database.DB.Delete(&models.ForwardingRule{}, id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func TriggerSyncHandler(c *gin.Context) {
	sync.GlobalSyncNow()
	c.JSON(http.StatusOK, gin.H{"status": "sync triggered"})
}

// IssueCertHandler 不再直接申请，而是下发任务给 Agent 执行
func IssueCertHandler(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var entry models.EntryNode
	if err := database.DB.Where("domain = ?", req.Domain).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到绑定该域名的节点"})
		return
	}

	// 标记该节点有待处理的证书任务
	entry.CertTask = true
	database.DB.Save(&entry)

	c.JSON(http.StatusOK, gin.H{
		"message": "申请指令已下发！中转机将在下次同步时（约1分钟内）自动开始申请。申请成功后证书将自动同步回来。",
	})
}

// UploadCertHandler 供 Agent 申请成功后回传证书内容
func UploadCertHandler(c *gin.Context) {
	var req struct {
		Domain   string `json:"domain"`
		CertBody string `json:"cert_body"`
		KeyBody  string `json:"key_body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data"})
		return
	}

	var entries []models.EntryNode
	if err := database.DB.Find(&entries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query entries"})
		return
	}

	var entry *models.EntryNode
	for i := range entries {
		dbDomains := strings.Split(entries[i].Domain, ",")
		for _, d := range dbDomains {
			if strings.TrimSpace(d) == req.Domain {
				entry = &entries[i]
				break
			}
		}
		if entry != nil {
			break
		}
	}

	if entry == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}

	entry.CertBody = req.CertBody
	entry.KeyBody = req.KeyBody
	entry.CertTask = false // 任务完成，清除标志

	// 自动更新路径为 Agent 默认安装路径，让用户在 UI 上无感
	entry.Certificate = "/etc/stealthforward/certs/" + req.Domain + "/cert.crt"
	entry.Key = "/etc/stealthforward/certs/" + req.Domain + "/cert.key"

	database.DB.Save(entry)

	c.JSON(http.StatusOK, gin.H{"message": "证书备份成功"})
}

// NodeMapping 管理接口
func ListNodeMappingsHandler(c *gin.Context) {
	var mappings []models.NodeMapping
	database.DB.Find(&mappings)
	c.JSON(http.StatusOK, mappings)
}

func CreateNodeMappingHandler(c *gin.Context) {
	var mapping models.NodeMapping
	if err := c.ShouldBindJSON(&mapping); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	database.DB.Save(&mapping)
	// 创建映射后立即尝试同步该节点数据
	sync.GlobalSyncNow()
	c.JSON(http.StatusOK, mapping)
}

func DeleteNodeMappingHandler(c *gin.Context) {
	id := c.Param("id")
	database.DB.Delete(&models.NodeMapping{}, id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func UpdateNodeMappingHandler(c *gin.Context) {
	id := c.Param("id")
	var mapping models.NodeMapping
	if err := database.DB.First(&mapping, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "mapping not found"})
		return
	}

	if err := c.ShouldBindJSON(&mapping); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database.DB.Save(&mapping)
	sync.GlobalSyncNow()
	c.JSON(http.StatusOK, mapping)
}

// ReportTrafficHandler 接收 Agent 上报的流量数据
func ReportTrafficHandler(c *gin.Context) {
	var report models.NodeTrafficReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 将流量数据存入同步模块进行汇总
	sync.CollectTraffic(report)

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// ExportConfigHandler 导出系统核心配置（备份用）
func ExportConfigHandler(c *gin.Context) {
	var backup struct {
		Entries  []models.EntryNode   `json:"entries"`
		Exits    []models.ExitNode    `json:"exits"`
		Mappings []models.NodeMapping `json:"mappings"`
	}

	database.DB.Find(&backup.Entries)
	database.DB.Find(&backup.Exits)
	database.DB.Find(&backup.Mappings)

	c.JSON(http.StatusOK, backup)
}

// ImportConfigHandler 导入系统核心配置（恢复用）
func ImportConfigHandler(c *gin.Context) {
	var backup struct {
		Entries  []models.EntryNode   `json:"entries"`
		Exits    []models.ExitNode    `json:"exits"`
		Mappings []models.NodeMapping `json:"mappings"`
	}

	if err := c.ShouldBindJSON(&backup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的备份文件格式"})
		return
	}

	// 使用事务确保操作安全
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// 1. 清空旧数据 (按需)
		tx.Exec("DELETE FROM entry_nodes")
		tx.Exec("DELETE FROM exit_nodes")
		tx.Exec("DELETE FROM node_mappings")
		tx.Exec("DELETE FROM forwarding_rules") // 清空规则，等待下次同步重建

		// 2. 写入新数据
		if len(backup.Entries) > 0 {
			if err := tx.Create(&backup.Entries).Error; err != nil {
				return err
			}
		}
		if len(backup.Exits) > 0 {
			if err := tx.Create(&backup.Exits).Error; err != nil {
				return err
			}
		}
		if len(backup.Mappings) > 0 {
			if err := tx.Create(&backup.Mappings).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复失败: " + err.Error()})
		return
	}

	// 触发一次全量同步
	sync.GlobalSyncNow()

	c.JSON(http.StatusOK, gin.H{"message": "配置恢复成功，已触发全量同步"})
}

// RotateIPHandler 主动更换 AWS 节点 IP (支持 EC2 和 Lightsail)
func RotateIPHandler(c *gin.Context) {
	nodeIDStr := c.Param("id")
	// 校验节点是否存在
	var entry models.EntryNode
	if err := database.DB.First(&entry, "id = ?", nodeIDStr).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry node not found"})
		return
	}

	var req struct {
		Region     string `json:"region"`
		InstanceID string `json:"instance_id"`
		ZoneName   string `json:"zone_name"`
		RecordName string `json:"record_name"`
	}
	// 可选绑定 JSON
	c.ShouldBindJSON(&req)

	// 优先使用数据库中绑定的信息
	if req.Region == "" {
		req.Region = entry.CloudRegion
	}
	if req.InstanceID == "" {
		req.InstanceID = entry.CloudInstanceID
	}
	if req.RecordName == "" {
		req.RecordName = entry.CloudRecordName
	}

	// 检查 ZoneName
	if req.ZoneName == "" {
		var setting models.SystemSetting
		if err := database.DB.Where("key = ?", "cloudflare.default_zone").First(&setting).Error; err == nil {
			req.ZoneName = setting.Value
		}
	}

	// 最终校验
	if req.Region == "" || req.InstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未绑定云平台区域或实例 ID，请在编辑中绑定"})
		return
	}

	var newIP string
	var err error

	// 执行换 IP 逻辑 (路由)
	if entry.CloudProvider == "aws_lightsail" {
		newIP, err = cloud.RotateLightsailIPWithDNS(c.Request.Context(), req.Region, req.InstanceID, req.ZoneName, req.RecordName)
	} else {
		// 默认为 AWS EC2
		newIP, err = cloud.RotateIPForInstance(c.Request.Context(), req.Region, req.InstanceID, req.ZoneName, req.RecordName)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Rotate failed: " + err.Error()})
		return
	}

	// 成功后，更新数据库中的 IP 字段
	entry.IP = newIP
	database.DB.Save(&entry)

	c.JSON(http.StatusOK, gin.H{
		"message": "IP 更换成功",
		"new_ip":  newIP,
	})
}
