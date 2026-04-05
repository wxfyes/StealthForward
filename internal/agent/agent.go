package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wangn9900/StealthForward/internal/generator"
	"github.com/wangn9900/StealthForward/internal/models"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

const (
	// Version 客户端版本号
	Version = "v3.6.76 (Cert Renewal & Manual Sync)"
)

type Config struct {
	ControllerAddr string
	NodeID         int
	LocalConfigDir string
	MasqueradeDir  string
	SingBoxPath    string
	AdminToken     string
	UseInternal    bool // 是否使用内置内核 (支持精准流量统计)
}

type Agent struct {
	cfg             Config
	lastConfig      string
	box             *box.Box
	hs              *HookServer
	client          *http.Client
	externalTraffic map[uint][2]int64
	trafficMu       sync.Mutex
}

func NewAgent(cfg Config) *Agent {
	log.Printf("StealthForward Agent %s", Version)
	// 确保目录存在
	dirs := []string{cfg.LocalConfigDir, cfg.MasqueradeDir}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			os.MkdirAll(d, 0755)
		}
	}
	a := &Agent{
		cfg:             cfg,
		client:          &http.Client{Timeout: 10 * time.Second},
		externalTraffic: make(map[uint][2]int64),
	}
	// 启动时确保伪装页存在
	a.EnsureMasquerade()
	log.Printf("Masquerade directory: %s", cfg.MasqueradeDir)

	// 启动定时上报任务
	go a.reportTrafficLoop()
	return a
}

// FetchConfig 从 Controller 获取最新的 Sing-box 配置
func (a *Agent) FetchConfig() (string, error) {
	url := fmt.Sprintf("%s/api/v1/node/%d/config", a.cfg.ControllerAddr, a.cfg.NodeID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	if a.cfg.AdminToken != "" {
		req.Header.Set("Authorization", a.cfg.AdminToken)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("controller returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ApplyConfig 将配置保存到本地并尝试重启 Sing-box
func (a *Agent) ApplyConfig(configStr string) error {
	// HOTFIX: 强制修复 AnyTLS 配置问题 (Padding + ALPN)
	var rawCfg map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &rawCfg); err == nil {
		fixed := false
		if inbounds, ok := rawCfg["inbounds"].([]interface{}); ok {
			for _, ib := range inbounds {
				if inbound, ok := ib.(map[string]interface{}); ok {
					// 1. 检查是否存在 padding_scheme 且通过字符串传递
					if ps, ok := inbound["padding_scheme"].(string); ok && ps != "" {
						var psArr []string
						if err := json.Unmarshal([]byte(ps), &psArr); err == nil {
							inbound["padding_scheme"] = psArr
							fixed = true
						} else {
							delete(inbound, "padding_scheme")
							fixed = true
						}
					}

					// 2. 强制注入 ALPN 并根据协议优化 Sniff
					if tlsVal, ok := inbound["tls"]; ok {
						if tls, ok := tlsVal.(map[string]interface{}); ok {
							if tls["alpn"] == nil {
								tls["alpn"] = []string{"h2", "http/1.1"}
								fixed = true
							}
						}
					}

					if t, ok := inbound["type"].(string); ok && (t == "anytls" || t == "vless") {
						// 对于特定流控协议，放宽或关闭嗅探以提升握手稳定性
						if t == "anytls" {
							inbound["sniff"] = false
							delete(inbound, "sniff_timeout")
							fixed = true
						}
					}
				}
			}
		}

		// 3. HOTFIX: 强制修复 127.0.0.1 落地为 Direct
		// 防止 Generator 逻辑未生效导致连接拒绝
		if outbounds, ok := rawCfg["outbounds"].([]interface{}); ok {
			outFixed := false
			for _, ob := range outbounds {
				if outbound, ok := ob.(map[string]interface{}); ok {
					// 兼容性修复: 移除不支持的 tcp_keep_alive_interval 字段
					if _, ok := outbound["tcp_keep_alive_interval"]; ok {
						delete(outbound, "tcp_keep_alive_interval")
						outFixed = true
					}

					// 检查是否为指向 127.0.0.1 的 Shadowsocks
					if srv, ok := outbound["server"].(string); ok && (srv == "127.0.0.1" || srv == "localhost") {
						if t, ok := outbound["type"].(string); ok && t == "shadowsocks" {
							// 强制转换为 Direct
							outbound["type"] = "direct"
							delete(outbound, "server")
							delete(outbound, "server_port")
							delete(outbound, "method")
							delete(outbound, "password")
							delete(outbound, "plugin")
							delete(outbound, "plugin_opts")
							outFixed = true
							// log.Printf("[Agent] Hot-fixed local exit to direct: %v", outbound["tag"])
						}
					}
				}
			}
			if outFixed {
				fixed = true
			}
		}

		if fixed {
			if newBytes, err := json.MarshalIndent(rawCfg, "", "  "); err == nil {
				configStr = string(newBytes)
			}
		}
	}

	// 如果配置没变，跳过
	if configStr == a.lastConfig {
		return nil
	}

	// 解析配置以处理 Provision 文件下发
	var fullConfig struct {
		Provision map[string]string `json:"provision"`
	}
	if err := json.Unmarshal([]byte(configStr), &fullConfig); err == nil {
		for path, content := range fullConfig.Provision {
			if path == "" {
				continue
			}
			dir := filepath.Dir(path)
			os.MkdirAll(dir, 0755)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				log.Printf("Failed to provision file %s: %v", path, err)
			} else {
				log.Printf("Synthesized missing file from controller: %s", path)
			}
		}
	}

	// 2. 移除 root 级的 provision 字段后再写入文件，防止内核解码失败
	var configMap map[string]interface{}
	finalConfigStr := configStr
	if err := json.Unmarshal([]byte(configStr), &configMap); err == nil {
		delete(configMap, "provision")
		if bytes, err := json.MarshalIndent(configMap, "", "  "); err == nil {
			finalConfigStr = string(bytes)
		}
	}

	configPath := filepath.Join(a.cfg.LocalConfigDir, "config.json")

	// 3. 写入文件
	err := os.WriteFile(configPath, []byte(finalConfigStr), 0644)
	if err != nil {
		return err
	}

	a.lastConfig = configStr
	log.Printf("New config applied to %s", configPath)

	// 3. 确保内核二进制文件存在，否则自动下载
	a.EnsureCoreInstalled()

	// 4. 重启 Sing-box 服务 (使用清洗过的 finalConfigStr)
	return a.RestartSingBox(finalConfigStr)
}

func (a *Agent) RestartSingBox(configStr string) error {
	if a.cfg.UseInternal {
		return a.UpdateInternalCore(configStr)
	}

	if runtime.GOOS == "windows" {
		log.Println("Windows detected, skipping service restart logic.")
		return nil
	}
	// ... (原逻辑) ...
	// 尝试重启我们的隔离服务
	cmd := exec.Command("systemctl", "restart", "stealth-core")
	if err := cmd.Run(); err != nil {
		log.Printf("Stealth-core restart failed, trying standard sing-box: %v", err)
		// 备选方案：尝试重启标准的 sing-box 服务
		if err := exec.Command("systemctl", "restart", "sing-box").Run(); err != nil {
			log.Printf("Standard sing-box restart also failed, trying direct reload.")
			return exec.Command(a.cfg.SingBoxPath, "check", "-c", filepath.Join(a.cfg.LocalConfigDir, "config.json")).Run()
		}
	}

	log.Println("Sing-box service restarted successfully.")
	return nil
}

func (a *Agent) UpdateInternalCore(configStr string) error {
	ctx := context.Background()
	ctx = box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())

	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(configStr))
	if err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}

	b, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return fmt.Errorf("create sing-box error: %s", err)
	}

	// 注入我们的统计钩子
	hs := &HookServer{
		counter: sync.Map{},
	}
	b.Router().AppendTracker(hs)

	// 热重载：先停止旧内核释放端口，再启动新内核
	if a.box != nil {
		log.Println("Hot reload: stopping old core to release ports...")
		a.box.Close()
		time.Sleep(200 * time.Millisecond) // 等待端口释放
	}

	// 启动新内核，带重试机制防止端口未完全释放
	var startErr error
	for retry := 0; retry < 3; retry++ {
		startErr = b.Start()
		if startErr == nil {
			break // 启动成功
		}
		log.Printf("Start attempt %d failed: %v, retrying...", retry+1, startErr)
		time.Sleep(500 * time.Millisecond) // 等待更长时间后重试
	}
	if startErr != nil {
		return fmt.Errorf("start new sing-box error after 3 retries: %s", startErr)
	}

	a.box = b
	a.hs = hs
	log.Println("Internal Sing-box core updated (Graceful). New core running.")
	return nil
}

func (a *Agent) reportTrafficLoop() {
	ticker := time.NewTicker(20 * time.Second) // 加快频率
	// pendingStats: [Email] -> [Up, Down]
	pendingUserStats := make(map[string][2]int64)

	for range ticker.C {
		userTraffic := []models.UserTraffic{}

		// 1. 尝试从内置核心获取用户级流量
		if a.hs != nil {
			newStats := a.hs.GetStats()
			for email, traffic := range newStats {
				val := pendingUserStats[email]
				val[0] += traffic[0]
				val[1] += traffic[1]
				pendingUserStats[email] = val
			}
			for email, traffic := range pendingUserStats {
				userTraffic = append(userTraffic, models.UserTraffic{
					UserEmail: email,
					Upload:    traffic[0],
					Download:  traffic[1],
				})
			}
		}

		// 2. 尝试获取节点级汇总流量 (支持外部魔改内核)
		var nodeUp, nodeDown int64
		// 这里未来可以扩展：通过 ss -ti 实时扫描并将数据存入 a.externalTraffic
		// 暂时先上报已发现的部分
		a.trafficMu.Lock()
		nodeUp = a.externalTraffic[uint(a.cfg.NodeID)][0]
		nodeDown = a.externalTraffic[uint(a.cfg.NodeID)][1]
		// 上报后清空，实现增量上报
		a.externalTraffic[uint(a.cfg.NodeID)] = [2]int64{0, 0}
		a.trafficMu.Unlock()

		// 即使没有用户流量，也允许上报（为了上报系统探针数据）
		// if len(userTraffic) == 0 && nodeUp == 0 && nodeDown == 0 {
		// 	continue
		// }

		report := models.NodeTrafficReport{
			NodeID:        uint(a.cfg.NodeID),
			Traffic:       userTraffic,
			TotalUpload:   nodeUp,
			TotalDownload: nodeDown,
			Stats:         GetSystemStats(), // 获取并附加系统状态
		}

		jsonData, _ := json.Marshal(report)
		url := fmt.Sprintf("%s/api/v1/node/%d/traffic", a.cfg.ControllerAddr, a.cfg.NodeID)
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if a.cfg.AdminToken != "" {
			req.Header.Set("Authorization", a.cfg.AdminToken)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := a.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				pendingUserStats = make(map[string][2]int64) // 只有成功才清空
			}
			resp.Body.Close()
		}
	}
}

func (a *Agent) RunOnce() {
	log.Println("Syncing state from controller...")

	// 1. 获取来自控制端的最新数据 (JSON 格式)
	url := fmt.Sprintf("%s/api/v1/node/%d/config", a.cfg.ControllerAddr, a.cfg.NodeID)
	req, _ := http.NewRequest("GET", url, nil)
	if a.cfg.AdminToken != "" {
		req.Header.Set("Authorization", a.cfg.AdminToken)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("Fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Config   string `json:"config"`
		CertTask bool   `json:"cert_task"`
		Domain   string `json:"domain"`
		CfToken  string `json:"cf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Failed to decode sync response: %v", err)
		return
	}

	// 2. 检查是否有证书申请任务，或者本地证书已失效 (主动防御)
	shouldIssue := result.CertTask
	if !shouldIssue && result.Domain != "" {
		certPath := "/etc/stealthforward/certs/" + result.Domain + "/cert.crt"
		if a.isCertExpiredSoon(certPath, 7) {
			log.Printf("[Auto-Check] Certificate for %s missing or expiring soon, triggering auto-renewal.", result.Domain)
			shouldIssue = true
		}
	}

	if shouldIssue && result.Domain != "" {
		log.Printf("Starting certificate issuance for domain: %s (Task: %v, CF_DNS: %v)", result.Domain, result.CertTask, result.CfToken != "")
		go a.IssueCertLocally(result.Domain, result.CfToken)
	}

	// 3. 应用配置
	if result.Config != "" {
		if err := a.ApplyConfig(result.Config); err != nil {
			log.Printf("Apply error: %v", err)
		}
	}
}

// IssueCertLocally 为域名申请 ACME 证书（优先 DNS-01，后退 Webroot/Standalone）
func (a *Agent) IssueCertLocally(domain string, cfToken string) {
	// 首先检查证书是否已经存在
	certDir := "/etc/stealthforward/certs/" + domain
	certFile := certDir + "/cert.crt"
	keyFile := certDir + "/cert.key"

	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// 增加检查：如果证书存在，判断是否快过期了 (小于 7 天则重新申请)
			if !a.isCertExpiredSoon(certFile, 7) {
				log.Printf("Certificate for %s already exists and is valid, skipping issuance.", domain)
				return
			}
			log.Printf("Certificate for %s is expired or about to expire, re-issuing...", domain)
		}
	}

	// 判断是否为 IP 地址 - ACME CA 不支持为 IP 签发证书
	if net.ParseIP(domain) != nil {
		log.Printf("[%s] Detected IP address. ACME CAs (Let's Encrypt, ZeroSSL) do not support IP certificates.", domain)
		log.Printf("[%s] Please manually place your certificate files at:", domain)
		log.Printf("  - Certificate: %s", certFile)
		log.Printf("  - Private Key: %s", keyFile)
		log.Printf("[%s] Skipping automatic certificate issuance.", domain)
		return
	}

	log.Printf("Starting local ACME issuance for %s...", domain)
	home, _ := os.UserHomeDir()
	acmePath := filepath.Join(home, ".acme.sh/acme.sh")

	// 探测 acme.sh 路径 (root / home / bin)
	paths := []string{
		acmePath, // /root/.acme.sh/acme.sh
		"/usr/local/bin/acme.sh",
		"/usr/bin/acme.sh",
	}

	foundPath := ""
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		log.Printf("acme.sh not found in common paths, installing now...")
		// 补齐依赖并安装
		installCmd := exec.Command("sh", "-c", "apt-get update && apt-get install -y socat curl || yum install -y socat curl && curl https://get.acme.sh | sh")
		if out, err := installCmd.CombinedOutput(); err != nil {
			log.Printf("Failed to auto-install acme.sh: %v, Output: %s", err, string(out))
			return
		}
		// 重新探测
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				foundPath = p
				break
			}
		}
		if foundPath == "" {
			log.Printf("Critical: acme.sh installed but still not found at expected paths.")
			return
		}
		log.Printf("acme.sh installed successfully at %s", foundPath)
	}
	acmePath = foundPath

	// 尝试自动匹配宝塔之类的 webroot
	btPath := "/www/wwwroot/" + domain
	webroot := "/var/www/html"
	if _, err := os.Stat(btPath); err == nil {
		webroot = btPath
	}

	// 默认使用 letsencrypt，如果受限可以考虑 zerossl
	caServer := "letsencrypt"
	email := "admin@" + domain

	// 1. 尝试注册账号
	log.Printf("Registering ACME account for %s...", email)
	exec.Command(acmePath, "--register-account", "-m", email, "--server", caServer).Run()

	var output []byte
	var err error
	var cmd *exec.Cmd

	// === 终极稳定方案：DNS-01 挑战 (如果有 CF_Token) ===
	if cfToken != "" {
		log.Printf("!!! CF_Token detected, using DNS-01 challenge for ultimate stability on multi-IP architectures !!!")
		os.Setenv("CF_Token", cfToken)
		
		dnsCmd := exec.Command(acmePath, "--issue", "--server", caServer, "--dns", "dns_cf", "-d", domain, "--force")
		output, err = dnsCmd.CombinedOutput()
		
		if err == nil {
			log.Printf("DNS-01 challenge succeeded for %s via Cloudflare!", domain)
			goto InstallCert // 直接跳转到安装和上传步骤
		} else {
			outputStr := string(output)
			log.Printf("DNS-01 challenge failed: %s. Retrying with ZeroSSL...", outputStr)
			if strings.Contains(outputStr, "rateLimited") {
				caServer = "zerossl"
				exec.Command(acmePath, "--register-account", "-m", email, "--server", caServer).Run()
				dnsCmd = exec.Command(acmePath, "--issue", "--server", caServer, "--dns", "dns_cf", "-d", domain, "--force")
				output, err = dnsCmd.CombinedOutput()
			}
			
			if err == nil {
				log.Printf("DNS-01 challenge succeeded for %s with ZeroSSL via Cloudflare!", domain)
				goto InstallCert
			}
			log.Printf("DNS-01 mode completely failed. Falling back to HTTP-01 modes...")
		}
	}

	// 2. 尝试第一种方式：Webroot 模式 (配合 Nginx/Apache)
	log.Printf("Trying ACME issuance via Webroot (%s) using CA: %s...", webroot, caServer)
	cmd = exec.Command(acmePath, "--issue", "--server", caServer, "-d", domain, "-w", webroot, "--force")
	output, err = cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		
		// 智能感知：如果是负载均衡分流导致的验证失败，或者遭遇限流，自动切换到 ZeroSSL
		if strings.Contains(outputStr, "rateLimited") || strings.Contains(outputStr, "Invalid response") {
			log.Printf("!!! ACME Challenge failed (Rate Limit or Multi-IP routing off) !!! Switching to ZeroSSL...")
			caServer = "zerossl"
			exec.Command(acmePath, "--register-account", "-m", email, "--server", caServer).Run()
		}
		
		log.Printf("Webroot mode failed, trying Standalone mode with %s (temporarily stopping Nginx)...", caServer)

		// 3. 尝试第二种方式：Standalone 模式
		exec.Command("systemctl", "stop", "nginx").Run()
		exec.Command("sh", "-c", "apt-get install -y socat || yum install -y socat").Run()

		var standaloneCmd *exec.Cmd
		standaloneCmd = exec.Command(acmePath, "--issue", "--server", caServer, "-d", domain, "--standalone", "--force")
		output, err = standaloneCmd.CombinedOutput()
		
		// 如果 Standalone 也因为 Let's encrypt 限流失败 (可能是刚才没切换)
		if err != nil && caServer != "zerossl" && strings.Contains(string(output), "rateLimited") {
			log.Printf("!!! Let's Encrypt Rate Limit Hit on Standalone !!! Switching to ZeroSSL and retrying...")
			caServer = "zerossl"
			exec.Command(acmePath, "--register-account", "-m", email, "--server", caServer).Run()
			standaloneCmd = exec.Command(acmePath, "--issue", "--server", caServer, "-d", domain, "--standalone", "--force")
			output, err = standaloneCmd.CombinedOutput()
		}

		exec.Command("systemctl", "start", "nginx").Run()

		if err != nil {
			log.Printf("Critical: ACME issuance completely failed for %s. Output: %s", domain, string(output))
			return
		}
	}

InstallCert:
	log.Printf("Successfully issued certificate for %s", domain)

	// 安装证书到本地指定目录
	// 注意：acme.sh 安装时会自动提取 fullchain
	certDir = "/etc/stealthforward/certs/" + domain
	os.MkdirAll(certDir, 0755)
	certFile = certDir + "/cert.crt"
	keyFile = certDir + "/cert.key"

	cmd = exec.Command(acmePath, "--install-cert", "-d", domain,
		"--fullchain-file", certFile,
		"--key-file", keyFile)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to install cert: %v", err)
		return
	}

	// 回传给 Controller 备份
	cb, _ := os.ReadFile(certFile)
	kb, _ := os.ReadFile(keyFile)

	uploadURL := fmt.Sprintf("%s/api/v1/entries/upload-cert", a.cfg.ControllerAddr)
	payload := map[string]string{
		"domain":    domain,
		"cert_body": string(cb),
		"key_body":  string(kb),
	}
	jsonPayload, _ := json.Marshal(payload)

	postReq, _ := http.NewRequest("POST", uploadURL, bytes.NewBuffer(jsonPayload))
	if a.cfg.AdminToken != "" {
		postReq.Header.Set("Authorization", a.cfg.AdminToken)
	}
	postReq.Header.Set("Content-Type", "application/json")

	respUpload, err := a.client.Do(postReq)
	if err == nil && respUpload.StatusCode == http.StatusOK {
		log.Printf("Certificate issued and backed up to controller for %s", domain)
	} else {
		log.Printf("Failed to backup certificate to controller")
	}
}

// EnsureMasquerade 检查并生成唯一的伪装页面
func (a *Agent) EnsureMasquerade() {
	indexFile := filepath.Join(a.cfg.MasqueradeDir, "index.html")
	info, err := os.Stat(indexFile)
	if os.IsNotExist(err) || (err == nil && info.Size() < 500) {
		log.Println("Generating unique masquerade site...")
		html := generator.GenerateMasqueradeHTML()
		os.WriteFile(indexFile, []byte(html), 0644)
	}
}

// StartMasqueradeServer 在后台启动一个轻量级的 HTTP 服务器用于回落
func (a *Agent) StartMasqueradeServer(port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	log.Printf("Starting masquerade server on %s", addr)
	fs := http.FileServer(http.Dir(a.cfg.MasqueradeDir))
	http.Handle("/", fs)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("Masquerade server error: %v", err)
		}
	}()
}
func (a *Agent) EnsureCoreInstalled() {
	path := a.cfg.SingBoxPath
	if _, err := os.Stat(path); err == nil {
		return
	}

	log.Printf("Core binary missing at %s, attempting to download...", path)
	os.MkdirAll(filepath.Dir(path), 0755)

	// 从 GitHub 下载最新的官方内核 (推荐版本 v1.10.x)
	version := "v1.10.7"
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/%s/sing-box-%s-linux-%s.tar.gz", version, version[1:], arch)

	log.Printf("Downloading core from: %s", url)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("curl -L %s | tar -xz --strip-components=1 -C /tmp && mv /tmp/sing-box %s && chmod +x %s", url, path, path))
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to download core: %v, Output: %s", err, string(out))
		// 备选地址 (如果 GitHub 慢)
		return
	}
	log.Printf("Core binary installed successfully to %s", path)
}

// isCertExpiredSoon 检查证书是否在指定天数内过期
func (a *Agent) isCertExpiredSoon(certPath string, days int) bool {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return true
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}

	// 剩余时间小于指定天数，或者已经过期
	threshold := time.Duration(days) * 24 * time.Hour
	return time.Until(cert.NotAfter) < threshold
}
