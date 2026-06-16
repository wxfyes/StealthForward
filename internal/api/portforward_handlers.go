package api

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/models"
)

// ListPortForwardsHandler 获取所有免审计端口转发规则
func ListPortForwardsHandler(c *gin.Context) {
	var rules []models.PortForward
	if err := database.DB.Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list port forwards: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, rules)
}

// CreatePortForwardHandler 创建端口转发规则
func CreatePortForwardHandler(c *gin.Context) {
	var rule models.PortForward
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request data: " + err.Error()})
		return
	}

	// 1. 校验端口范围
	if rule.ListenPort < 1 || rule.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "监听端口必须在 1 到 65535 之间"})
		return
	}

	// 2. 校验端口是否被该入口的其他转发规则或主入口占用
	var count int64
	// 2.1 检查是否被其他 PortForward 占用
	database.DB.Model(&models.PortForward{}).Where("entry_node_id = ? AND listen_port = ?", rule.EntryNodeID, rule.ListenPort).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被其他端口转发规则占用"})
		return
	}

	// 2.2 检查是否被 NodeMapping (V2board 分流端口) 占用
	database.DB.Model(&models.NodeMapping{}).Where("entry_node_id = ? AND port = ?", rule.EntryNodeID, rule.ListenPort).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被 V2board 节点分流端口占用"})
		return
	}

	// 2.3 检查是否被入口主监听端口占用
	var entry models.EntryNode
	if err := database.DB.First(&entry, rule.EntryNodeID).Error; err == nil {
		if entry.Port == rule.ListenPort {
			c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被入口节点主监听端口占用"})
			return
		}
	}

	// 3. 设置默认值并保存
	if rule.Status == "" {
		rule.Status = "running"
	}
	rule.Upload = 0
	rule.Download = 0

	if err := database.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rule: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// UpdatePortForwardHandler 更新端口转发规则
func UpdatePortForwardHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id"})
		return
	}

	var existing models.PortForward
	if err := database.DB.First(&existing, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var req models.PortForward
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request data: " + err.Error()})
		return
	}

	// 端口校验逻辑（如果端口有修改）
	if req.ListenPort != existing.ListenPort {
		if req.ListenPort < 1 || req.ListenPort > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "监听端口必须在 1 到 65535 之间"})
			return
		}

		var count int64
		// 检查 PortForward
		database.DB.Model(&models.PortForward{}).Where("entry_node_id = ? AND listen_port = ? AND id != ?", req.EntryNodeID, req.ListenPort, existing.ID).Count(&count)
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被其他端口转发规则占用"})
			return
		}

		// 检查 NodeMapping
		database.DB.Model(&models.NodeMapping{}).Where("entry_node_id = ? AND port = ?", req.EntryNodeID, req.ListenPort).Count(&count)
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被 V2board 节点分流端口占用"})
			return
		}

		// 检查主入口
		var entry models.EntryNode
		if err := database.DB.First(&entry, req.EntryNodeID).Error; err == nil {
			if entry.Port == req.ListenPort {
				c.JSON(http.StatusBadRequest, gin.H{"error": "端口已被入口节点主监听端口占用"})
				return
			}
		}

		existing.ListenPort = req.ListenPort
	}

	// 更新其他字段
	existing.Name = req.Name
	existing.TargetAddr = req.TargetAddr
	existing.Type = req.Type
	existing.TunnelType = req.TunnelType
	if req.Status != "" {
		existing.Status = req.Status
	}

	if err := database.DB.Save(&existing).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rule: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, existing)
}

// DeletePortForwardHandler 删除端口转发规则
func DeletePortForwardHandler(c *gin.Context) {
	id := c.Param("id")
	if err := database.DB.Delete(&models.PortForward{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete rule: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ClearPortForwardTrafficHandler 清空单条规则的流量
func ClearPortForwardTrafficHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id"})
		return
	}

	var rule models.PortForward
	if err := database.DB.First(&rule, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	rule.Upload = 0
	rule.Download = 0
	if err := database.DB.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear traffic: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "流量已清零"})
}

// TogglePortForwardHandler 暂停/启动端口转发规则
func TogglePortForwardHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id"})
		return
	}

	var rule models.PortForward
	if err := database.DB.First(&rule, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	if rule.Status == "running" {
		rule.Status = "paused"
	} else {
		rule.Status = "running"
	}

	if err := database.DB.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to toggle status: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// DiagnosePortForwardHandler 规则连通性诊断接口
func DiagnosePortForwardHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id"})
		return
	}

	var rule models.PortForward
	if err := database.DB.First(&rule, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	// 1. 获取入口节点信息
	var entry models.EntryNode
	if err := database.DB.First(&entry, rule.EntryNodeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry node not found"})
		return
	}

	// 2. 诊断 Inbound (测试中控到中转入口机 IP:监听端口 的联通性)
	inboundAddr := net.JoinHostPort(entry.IP, strconv.Itoa(rule.ListenPort))
	if entry.IP == "" {
		inboundAddr = net.JoinHostPort(entry.Domain, strconv.Itoa(rule.ListenPort))
	}

	inboundOK := false
	var inboundMs int64 = 0

	t1 := time.Now()
	conn1, err1 := net.DialTimeout("tcp", inboundAddr, 2*time.Second)
	if err1 == nil {
		inboundOK = true
		inboundMs = time.Since(t1).Milliseconds()
		conn1.Close()
	}

	// 3. 诊断 Outbound (测试中控到落地目标地址的联通性)
	outboundOK := false
	var outboundMs int64 = 0

	t2 := time.Now()
	conn2, err2 := net.DialTimeout("tcp", rule.TargetAddr, 2*time.Second)
	if err2 == nil {
		outboundOK = true
		outboundMs = time.Since(t2).Milliseconds()
		conn2.Close()
	}

	// 返回诊断详情的 JSON 供前端弹窗展示
	c.JSON(http.StatusOK, gin.H{
		"rule_id":        rule.ID,
		"rule_name":      rule.Name,
		"entry_name":     entry.Name,
		"inbound_addr":   inboundAddr,
		"inbound_ok":     inboundOK,
		"inbound_ms":     inboundMs,
		"outbound_addr":  rule.TargetAddr,
		"outbound_ok":    outboundOK,
		"outbound_ms":    outboundMs,
		"backend_tasks":  1,
		"backend_failed": 0,
	})
}
