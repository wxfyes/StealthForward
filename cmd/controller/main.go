package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wangn9900/StealthForward/internal/api"
	"github.com/wangn9900/StealthForward/internal/database"
	"github.com/wangn9900/StealthForward/internal/license"
	"github.com/wangn9900/StealthForward/internal/sync"
)

func main() {
	// 0. 解析参数
	listenAddr := flag.String("addr", ":8090", "Listen address (e.g. :8090 or 127.0.0.1:8090)")
	flag.Parse()

	// === 授权验证（可选） ===
	// 管理员模式：设置STEALTH_ADMIN_TOKEN即可使用，不依赖授权服务器
	// 用户模式：需要在登录时输入License Key验证
	adminToken := os.Getenv("STEALTH_ADMIN_TOKEN")
	licenseKey := os.Getenv("STEALTH_LICENSE_KEY")

	// 尝试从持久化文件加载 Key (优先级高于环境变量，或者作为补充)
	if licenseKey == "" {
		licenseKey = license.LoadKey()
	}

	if licenseKey != "" && os.Getenv("SKIP_LICENSE") != "true" {
		// 有License Key时尝试预验证
		log.Println("正在验证授权...")
		// 确保 license 模块使用正确的 key
		license.SetKey(licenseKey)

		if err := license.Verify(); err != nil {
			log.Printf("⚠️ 授权验证失败: %v", err)
			log.Println("⚠️ 系统将以受限模式启动，请在 Web 端重新输入 Key 激活")
		} else {
			info := license.GetInfo()
			log.Printf("✅ 授权验证成功 [%s] 有效期至 %s",
				info.Level,
				info.ExpiresAt.Format("2006-01-02"))
			go license.StartHeartbeat()
			// 注册熔断回调：当 Heartbeat 失败时，直接杀掉 Controller 进程
			license.RegisterServiceStopper(func() {
				log.Println("⚠️ 授权失效或过期！系统已自动切换至 [只读/维护模式]。")
				log.Println("👉 所有管理功能已被冻结，请登录 Web 面板重新激活授权。")
				// 关键修改：不再执行 os.Exit(1)，保持进程存活以允许用户访问 Web 端进行续费
			})
		}
	} else if adminToken != "" {
		log.Println("📌 管理员模式启动（无需授权验证）")
	} else {
		log.Println("⚠️ 未配置授权Key或管理员密码，即将在 Web 端等待 License Key 激活...")
	}

	// 1. 初始化数据库
	database.InitDB()

	// 2. 启动 V2Board 自动同步任务与流量上报任务
	sync.StartV2boardSync()
	sync.StartTrafficReporting()
	sync.InitTrafficFromDB() // 从数据库恢复流量统计

	// 2. 设置 Gin 路由
	r := gin.Default()

	// --- 鉴权中间件 ---
	// adminToken 已在上方声明
	// --- 鉴权中间件 ---
	// adminToken 已在上方声明
	authMiddleware := func(c *gin.Context) {
		// 1. 确定管理员密码
		adminPass := os.Getenv("STEALTH_ADMIN_TOKEN")
		var dbSetting models.SystemSetting
		if err := database.DB.Where("key = ?", models.ConfigKeyAdminPassword).First(&dbSetting).Error; err == nil && dbSetting.Value != "" {
			adminPass = dbSetting.Value
		}

		// 2. 确定通信密钥
		commToken := ""
		var commSetting models.SystemSetting
		if err := database.DB.Where("key = ?", models.ConfigKeyCommunicationToken).First(&commSetting).Error; err == nil {
			commToken = commSetting.Value
		}

		// 如果两者都未配置（极端情况），则视为不需要鉴权
		if adminPass == "" && commToken == "" {
			// 直接放行
		} else {
			// 获取请求 Token
			token := c.GetHeader("Authorization")
			if token == "" {
				token = c.Query("token")
			}

			// 验证 Token (匹配任意一个即可通过)
			isAuth := false
			if adminPass != "" && token == adminPass {
				isAuth = true
			}
			if !isAuth && commToken != "" && token == commToken {
				isAuth = true
			}

			if !isAuth {
				c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
				return
			}
		}

		// --- 商业授权熔断机制 ---
		// 如果未激活，仅允许:
		// 1. GET 请求 (只读查看)
		// 2. /api/v1/system/activate (激活操作)
		// 其他写操作一律拦截
		if !license.IsValid() {
			isRead := c.Request.Method == "GET" || c.Request.Method == "OPTIONS" || c.Request.Method == "HEAD"
			isActivate := strings.HasSuffix(c.Request.URL.Path, "/activate")

			if !isRead && !isActivate {
				c.AbortWithStatusJSON(403, gin.H{
					"error": "🚫 System is in View-Only mode. Please activate your license to perform this action.",
					"code":  "LICENSE_REQUIRED",
				})
				return
			}
		}

		c.Next()
	}

	// 存活检查
	r.GET("/api/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	// 静态文件目录 (极致鲁棒探测)
	cwd, _ := os.Getwd()
	searchPaths := []string{
		"./web",
		filepath.Join(cwd, "web"),
		"/usr/local/share/stealthforward/web",
	}

	finalWebRoot := ""
	for _, p := range searchPaths {
		if _, err := os.Stat(filepath.Join(p, "index.html")); err == nil {
			finalWebRoot, _ = filepath.Abs(p)
			break
		}
	}

	if finalWebRoot != "" {
		log.Printf("成功定位 Web 目录: %s", finalWebRoot)
		r.Static("/static", filepath.Join(finalWebRoot, "static"))
		r.Static("/assets", filepath.Join(finalWebRoot, "assets"))

		// 安全加载安装脚本，防止因文件缺失导致进程崩溃 (502)
		if _, err := os.Stat("./scripts/install.sh"); err == nil {
			r.StaticFile("/install.sh", "./scripts/install.sh")
			r.StaticFile("/static/install.sh", "./scripts/install.sh")
		} else {
			log.Printf("警告: 未找到 ./scripts/install.sh，相关下载链接将不可用")
		}

		r.StaticFile("/dashboard", filepath.Join(finalWebRoot, "index.html"))
		r.StaticFile("/", filepath.Join(finalWebRoot, "index.html"))

		r.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			// 如果是脚本请求但没命中 StaticFile，绝不准返回 HTML 兜底
			if strings.HasSuffix(path, ".sh") {
				c.Status(404)
				return
			}
			if !strings.HasPrefix(path, "/api/") {
				c.File(filepath.Join(finalWebRoot, "index.html"))
				return
			}
			c.Status(404)
		})
	} else {
		log.Printf("严重警告: 无法定位 web/index.html，请确保 web 文件夹在运行目录下。")
	}

	// 公开 API
	r.POST("/api/v1/auth/login", api.LoginHandler)

	// API 分组 (Protected)
	v1 := r.Group("/api/v1")
	v1.Use(authMiddleware)
	{
		// 系统设置
		v1.GET("/system/config", api.GetSystemConfigHandler)
		v1.POST("/system/config", api.UpdateSystemConfigHandler)
		v1.POST("/system/activate", api.ActivateLicenseHandler)

		// 节点管理 (Entry)
		v1.GET("/entries", api.ListEntryNodesHandler)
		v1.POST("/entries", api.RegisterNodeHandler)
		v1.DELETE("/entries/:id", api.DeleteEntryNodeHandler)
		v1.POST("/entries/issue-cert", api.IssueCertHandler)
		v1.POST("/entries/upload-cert", api.UploadCertHandler) // Agent 申请成功后回传

		// 落地管理 (Exit)
		v1.GET("/exits", api.ListExitNodesHandler)
		v1.POST("/exits", api.CreateExitNodeHandler)
		v1.DELETE("/exits/:id", api.DeleteExitNodeHandler)

		// 转发链路管理 (Rules)
		v1.GET("/rules", api.ListForwardingRulesHandler)
		v1.POST("/rules", api.CreateForwardingRuleHandler)
		v1.DELETE("/rules/:id", api.DeleteForwardingRuleHandler)

		// Agent 获取配置的核心接口
		v1.GET("/node/:id/config", api.GetConfigHandler)
		// Agent 上报流量的接口
		v1.POST("/node/:id/traffic", api.ReportTrafficHandler)

		// Agent 一键换 IP 接口 (AWS Only)
		// --- Cloud Instance Provisioning & Keys ---
		v1.POST("/cloud/instances", api.ProvisionInstanceHandler)
		v1.POST("/cloud/instances/terminate", api.TerminateInstanceHandler)
		v1.GET("/cloud/keys", api.ListKeysHandler)
		v1.GET("/cloud/keys/:name", api.DownloadKeyHandler) // 云平台辅助
		v1.GET("/cloud/regions", api.ListRegionsHandler)
		v1.GET("/cloud/images", api.ListImagesHandler)
		v1.GET("/cloud/instances", api.ListCloudInstancesHandler)
		v1.GET("/cloud/auto-detect", api.AutoDetectInstanceHandler)
		v1.POST("/cloud/rotate-ip", api.RotateIPHandler) // 通用入口
		v1.POST("/entries/:id/reprovision", api.ReprovisionNodeHandler)

		// --- Cloud Account Pool ---
		v1.GET("/cloud/accounts", api.ListCloudAccountsHandler)
		v1.POST("/cloud/accounts", api.CreateCloudAccountHandler)
		v1.PUT("/cloud/accounts/:id", api.UpdateCloudAccountHandler)
		v1.DELETE("/cloud/accounts/:id", api.DeleteCloudAccountHandler)

		// --- SSH Keys ---
		v1.GET("/system/ssh-keys", api.ListSSHKeysHandler)
		v1.POST("/system/ssh-keys", api.CreateSSHKeyHandler)
		v1.PUT("/system/ssh-keys/:id", api.UpdateSSHKeyHandler)
		v1.DELETE("/system/ssh-keys/:id", api.DeleteSSHKeyHandler)

		// --- Lightsail ---
		v1.GET("/cloud/lightsail/regions", api.ListLightsailRegionsHandler)
		v1.GET("/cloud/lightsail/bundles", api.ListLightsailBundlesHandler)
		v1.GET("/cloud/lightsail/blueprints", api.ListLightsailBlueprintsHandler)
		v1.POST("/cloud/lightsail/instances", api.ProvisionLightsailHandler)
		v1.POST("/cloud/lightsail/terminate", api.TerminateLightsailHandler)
		v1.POST("/cloud/lightsail/rotate-ip", api.RotateLightsailIPHandler)

		// --- Traffic Stats ---
		v1.GET("/traffic", api.GetTrafficStatsHandler)
		v1.DELETE("/traffic/entry/:id", api.ClearEntryTrafficHandler) // 清除入口节点流量
		v1.DELETE("/traffic/exit/:id", api.ClearExitTrafficHandler)   // 清除落地节点流量
		v1.DELETE("/traffic/all", api.ClearAllTrafficHandler)         // 清除所有流量

		// 分流映射管理 (NodeMappings)
		v1.GET("/mappings", api.ListNodeMappingsHandler)
		v1.POST("/mappings", api.CreateNodeMappingHandler)
		v1.PUT("/mappings/:id", api.UpdateNodeMappingHandler)
		v1.DELETE("/mappings/:id", api.DeleteNodeMappingHandler)

		// 触发 V2Board 同步
		v1.POST("/sync", api.TriggerSyncHandler)

		// 系统备份与恢复
		v1.GET("/system/backup", api.ExportConfigHandler)
		v1.POST("/system/restore", api.ImportConfigHandler)

		// --- License 授权信息 ---
		v1.GET("/license/info", api.GetLicenseInfoHandler)
	}

	log.Printf("StealthForward Controller is running on %s", *listenAddr)
	if err := r.Run(*listenAddr); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
