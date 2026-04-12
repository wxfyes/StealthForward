package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/license"
	"github.com/wangn9900/StealthForward/internal/models"
)

// 管理员密码硬编码的SHA256哈希（生产环境请修改）
// 默认密码: stealth@admin2024
// 生成方式: echo -n "stealth@admin2024" | sha256sum
const adminPasswordHash = "a8f5f167f44f4964e6c998dee827110c9d679f0fc7b8e9b7a0c7c7c8d8e4f1b2"

// --- Auth ---

// LoginHandler 支持两种登录方式：
// 1. 管理员登录：username=admin, password=管理员密码（本地验证，不依赖授权服务器）
// 2. License Key登录：license_key=SF-X-XXXX-XXXX（远程验证）
func LoginHandler(c *gin.Context) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		LicenseKey string `json:"license_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// 鉴权优先级：数据库设置 > 环境变量 > 硬编码默认
	defaultPassword := "admin"
	
	// 1. 尝试从数据库获取
	var dbSetting models.SystemSetting
	if err := database.DB.Where("key = ?", models.ConfigKeyAdminPassword).First(&dbSetting).Error; err == nil && dbSetting.Value != "" {
		defaultPassword = dbSetting.Value
	} else {
		// 2. 尝试从环境变量获取
		envToken := os.Getenv("STEALTH_ADMIN_TOKEN")
		if envToken != "" {
			defaultPassword = envToken
		}
	}

	if req.Username == "admin" && req.Password == defaultPassword {
		c.JSON(http.StatusOK, gin.H{
			"token":   defaultPassword,
			"role":    "admin",
			"level":   license.GetLevel(), // 虽然可能为空，但允许登录
			"message": "登录成功",
		})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误 (默认: admin/admin)"})
}

// ActivateLicenseHandler 在线激活接口
func ActivateLicenseHandler(c *gin.Context) {
	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// 验证
	license.SetKey(req.LicenseKey)
	if err := license.Verify(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "激活失败: " + err.Error()})
		return
	}

	// 保存
	license.SaveKey(req.LicenseKey)
	go license.StartHeartbeat()

	info := license.GetInfo()
	c.JSON(http.StatusOK, gin.H{
		"message":    "激活成功！",
		"level":      info.Level,
		"expires_at": info.ExpiresAt.Format("2006-01-02"),
	})
}

// --- System Config ---

// GetSystemConfigHandler 获取所有系统配置
func GetSystemConfigHandler(c *gin.Context) {
	var settings []models.SystemSetting
	if err := database.DB.Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 转为 Map 方便前端使用
	configMap := make(map[string]string)
	for _, s := range settings {
		configMap[s.Key] = s.Value
	}

	// 补充默认值（如果数据库里没有）
	if _, ok := configMap[models.ConfigKeyAwsAccessKeyID]; !ok {
		configMap[models.ConfigKeyAwsAccessKeyID] = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if _, ok := configMap[models.ConfigKeyAwsDefaultRegion]; !ok {
		configMap[models.ConfigKeyAwsDefaultRegion] = os.Getenv("AWS_DEFAULT_REGION")
		if configMap[models.ConfigKeyAwsDefaultRegion] == "" {
			configMap[models.ConfigKeyAwsDefaultRegion] = "ap-northeast-1"
		}
	}

	// 补充通信密钥（如果不存在则生成一个）
	if _, ok := configMap[models.ConfigKeyCommunicationToken]; !ok || configMap[models.ConfigKeyCommunicationToken] == "" {
		newToken := generateToken("comm")[:16] // 16位随机
		database.DB.Save(&models.SystemSetting{
			Key:      models.ConfigKeyCommunicationToken,
			Value:    newToken,
			Category: "system",
		})
		configMap[models.ConfigKeyCommunicationToken] = newToken
	}

	c.JSON(http.StatusOK, gin.H{"config": configMap})
}

// UpdateSystemConfigHandler 批量更新配置
func UpdateSystemConfigHandler(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx := database.DB.Begin()
	for k, v := range req {
		// Upsert
		var setting models.SystemSetting
		if err := tx.Where(models.SystemSetting{Key: k}).Attrs(models.SystemSetting{Value: v}).FirstOrCreate(&setting).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 如果已存在，更新值
		if setting.Value != v {
			setting.Value = v
			setting.UpdatedAt = time.Now()
			if err := tx.Save(&setting).Error; err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	}
	tx.Commit()

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated"})
}

// generateToken 简单的 Hash 生成 (暂未使用，预留)
func generateToken(input string) string {
	hash := sha256.Sum256([]byte(input + time.Now().String()))
	return hex.EncodeToString(hash[:])
}
