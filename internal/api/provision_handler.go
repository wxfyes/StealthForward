package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/models"
	"github.com/wangn9900/StealthForward/internal/remote"
)

// ReprovisionNodeHandler 触发远程节点的初始化流程 (BBR + 对接)
func ReprovisionNodeHandler(c *gin.Context) {
	id := c.Param("id")
	var entry models.EntryNode
	if err := database.DB.First(&entry, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}

	if entry.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node has no IP, please provision it first"})
		return
	}

	// 1. 获取 SSH 密钥
	var sshKey models.SSHKey
	if err := database.DB.First(&sshKey).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No SSH Provisioning Key found. Please add one in Settings."})
		return
	}

	// 2. 构造对接指令 (由主控地址和 Token 组成)
	host := c.Request.Host
	protocol := "http"
	if forwardedProto := c.GetHeader("X-Forwarded-Proto"); forwardedProto != "" {
		protocol = forwardedProto
	} else if c.Request.TLS != nil {
		protocol = "https"
	}
	controllerURL := fmt.Sprintf("%s://%s", protocol, host)

	// 鉴权 Token (优先使用通信密钥)
	validToken := os.Getenv("STEALTH_ADMIN_TOKEN")
	var commSetting models.SystemSetting
	if err := database.DB.Where("key = ?", models.ConfigKeyCommunicationToken).First(&commSetting).Error; err == nil && commSetting.Value != "" {
		validToken = commSetting.Value
	}

	installCmd := fmt.Sprintf(
		"export CTRL_ADDR='%s' && export NODE_ID='%d' && export CTRL_TOKEN='%s' && export CTRL_DOMAIN='%s' && "+
			"curl -fsSL https://raw.githubusercontent.com/wangn9900/StealthForward/main/scripts/install.sh | bash -s -- 2 >> /var/log/stealth-init.log 2>&1",
		controllerURL, entry.ID, validToken, entry.Domain,
	)

	// 如果用户有特殊的 install.sh 逻辑，也可以考虑用它
	// 但为了 BBR 和 RLimit，我们已经在 internal/remote 里写好了

	// 3. 异步执行
	go func() {
		cfg := remote.ProvisionConfig{
			Host:       entry.IP,
			Port:       22,
			User:       sshKey.User,
			PrivateKey: sshKey.KeyContent,
			AgentCmd:   installCmd,
		}

		if err := remote.RunProvisioning(cfg); err != nil {
			fmt.Printf("[Provision] Failed for node %d: %v\n", entry.ID, err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "自动化初始化任务已启动，请等待约 1-2 分钟。可在中转机 /var/log/stealth-init.log 查看进度。",
	})
}
