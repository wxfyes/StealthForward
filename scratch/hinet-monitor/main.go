package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config 结构体定义
type Config struct {
	HinetDomain          string `json:"hinet_domain"`
	HinetPort            int    `json:"hinet_port"`
	ChangeIPURL          string `json:"change_ip_url"`
	CheckIntervalSeconds int    `json:"check_interval_seconds"`
	AutoChangeEnabled    bool   `json:"auto_change_enabled"`
	ListenAddr           string `json:"listen_addr"`
	CFToken              string `json:"cf_token"`
	CFZoneID             string `json:"cf_zone_id"`
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"` // "info", "success", "warning", "error"
	Message   string `json:"message"`
}

// Global State
var (
	config        Config
	configMutex   sync.RWMutex
	logs          []LogEntry
	logsMutex     sync.Mutex
	statusIP      = "未知"
	statusState   = "checking" // "online", "blocked", "checking", "error"
	lastCheck     time.Time
	configFile    = "config.json"
	lastChangedIP        string // 新增：最后一次更换成功的新 IP
	lastFailedChangeTime time.Time // 新增：最后一次更换全部失败的时间
)

func init() {
	exePath, err := os.Executable()
	if err == nil {
		configFile = filepath.Join(filepath.Dir(exePath), "config.json")
	}
}

func addLog(logType, message string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      logType,
		Message:   message,
	}
	logs = append([]LogEntry{entry}, logs...) // 倒序排列，最新的在前面
	if len(logs) > 100 {
		logs = logs[:100] // 保留最近100条
	}
	log.Printf("[%s] %s", logType, message)
}

func loadConfig() {
	configMutex.Lock()
	defer configMutex.Unlock()

	// 默认配置
	config = Config{
		HinetDomain:          "hinet.example.com",
		HinetPort:            443,
		ChangeIPURL:          "https://newip.lala.gg/214higl.php",
		CheckIntervalSeconds: 60,
		AutoChangeEnabled:    true,
		ListenAddr:           ":18080",
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		saveConfigNoLock()
	}
}

func saveConfigNoLock() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, data, 0644)
}

func saveConfig(newCfg Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	config = newCfg
	saveConfigNoLock()
}

// 触发商家换 IP 接口并自动更新 Cloudflare DDNS
func triggerChangeIP() bool {
	configMutex.RLock()
	changeURL := config.ChangeIPURL
	cfToken := config.CFToken
	cfZoneID := config.CFZoneID
	domainStr := config.HinetDomain
	port := config.HinetPort
	configMutex.RUnlock()

	maxTries := 3
	for attempt := 1; attempt <= maxTries; attempt++ {
		addLog("warning", fmt.Sprintf("开始调用商家接口申请更换公网 IP (第 %d/%d 次尝试)...", attempt, maxTries))

		// 1. 根据 API 类型发送请求
		var newIP string
		isNewAPI := strings.Contains(changeURL, "hinetapi.php") || strings.Contains(changeURL, "type=change")

		if isNewAPI {
			addLog("info", "检测到新版 Hinet API，使用 GET 请求触发更换 IP...")
			resp, err := http.Get(changeURL)
			if err != nil {
				addLog("error", fmt.Sprintf("调用新版换 IP 接口失败: %v", err))
				if attempt == maxTries {
					return false
				}
				addLog("info", "等待 5 分钟后进行下一次更换尝试...")
				time.Sleep(5 * time.Minute)
				continue
			}
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			newIP = extractIPFromHTML(string(bodyBytes))
		} else {
			// 旧版接口使用 POST 请求
			resp, err := http.PostForm(changeURL, url.Values{"change_ip": {}})
			if err != nil {
				addLog("error", fmt.Sprintf("调用旧版换 IP 接口失败: %v", err))
				if attempt == maxTries {
					return false
				}
				addLog("info", "等待 5 分钟后进行下一次更换尝试...")
				time.Sleep(5 * time.Minute)
				continue
			}
			resp.Body.Close()
		}

		addLog("warning", "IP 申请指令已发送，等待 90 秒让 Hinet 重新拨号上线...")
		time.Sleep(90 * time.Second)

		// 2. 只有旧版接口需要从商家页面获取最新的公网 IP
		if !isNewAPI {
			for i := 0; i < 3; i++ { // 尝试最多 3 次，每次间隔 5 秒
				newIP = fetchNewIPFromMerchant(changeURL)
				if newIP != "" {
					break
				}
				addLog("warning", fmt.Sprintf("尝试获取新 IP 失败，等待 5 秒后重试 (%d/3)...", i+1))
				time.Sleep(5 * time.Second)
			}
		}

		if newIP == "" {
			addLog("error", "未能解析出新的公网 IP。")
			if attempt == maxTries {
				return false
			}
			addLog("info", "等待 5 分钟后进行下一次更换尝试...")
			time.Sleep(5 * time.Minute)
			continue
		}

		addLog("info", fmt.Sprintf("已获取到候选公网 IP: %s，开始进行 TCP 可用性自检...", newIP))

		// 3. 对新 IP 直接发起 TCP 握手自检
		address := net.JoinHostPort(newIP, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			// TCP 握手成功！证明 IP 可用且 VPS 端服务正常
			conn.Close()
			addLog("success", fmt.Sprintf("TCP 自检通过！新 IP %s 确认可用，开始同步到 Cloudflare...", newIP))

			configMutex.Lock()
			statusIP = newIP      // 提前更新状态 IP
			lastChangedIP = newIP // 记录期望的新 IP
			configMutex.Unlock()

			// 更新 Cloudflare DDNS
			if cfToken != "" {
				domains := parseDomainsList(domainStr)
				addLog("info", fmt.Sprintf("正在同步新 IP %s 到 Cloudflare (共有 %d 个域名)...", newIP, len(domains)))

				// 先获取用户 Token 下的所有 Zones
				zones := fetchCloudflareZones(cfToken)

				successCount := 0
				for _, d := range domains {
					zoneIDToUse := cfZoneID // 默认使用填写的 Zone ID

					// 智能匹配对应的 Zone ID
					for _, z := range zones {
						if strings.HasSuffix(d, z.Name) {
							zoneIDToUse = z.ID
							break
						}
					}

					if zoneIDToUse == "" {
						addLog("error", fmt.Sprintf("无法找到域名 %s 对应的 Zone ID，跳过更新", d))
						continue
					}

					if updateCloudflareDDNS(cfToken, zoneIDToUse, d, newIP) {
						addLog("success", fmt.Sprintf("Cloudflare DNS 同步更新成功！域名 %s 已指向新 IP: %s", d, newIP))
						successCount++
					} else {
						addLog("error", fmt.Sprintf("域名 %s 同步更新失败", d))
					}
				}

				if successCount == len(domains) {
					addLog("success", "所有绑定的域名 DNS 解析均已成功同步更新。")
				} else {
					addLog("warning", fmt.Sprintf("域名同步更新完成：成功 %d 个，失败 %d 个", successCount, len(domains)-successCount))
				}
			} else {
				addLog("info", "未配置 Cloudflare API 参数，跳过 DNS 自动更新。")
			}
			return true
		}

		// TCP 自检失败，说明 IP 可能被墙或 VPS 端服务未运行
		addLog("warning", fmt.Sprintf("新 IP %s TCP 自检失败（端口 %d 不通），可能该 IP 已被墙，准备重新换 IP...", newIP, port))
		if attempt == maxTries {
			addLog("error", "已连续更换 3 次 IP & TCP 自检全部失败！可能是您的 VPS 服务端程序已崩溃，或者端口配置错误，请登录 VPS 检查。")
			addLog("warning", fmt.Sprintf("将最后获取的 IP %s 强制同步到所有绑定的域名，以便您 SSH 登录排查...", newIP))

			configMutex.Lock()
			statusIP = newIP
			lastChangedIP = newIP
			configMutex.Unlock()

			if cfToken != "" {
				domains := parseDomainsList(domainStr)
				zones := fetchCloudflareZones(cfToken)
				for _, d := range domains {
					zoneIDToUse := cfZoneID
					for _, z := range zones {
						if strings.HasSuffix(d, z.Name) {
							zoneIDToUse = z.ID
							break
						}
					}
					if zoneIDToUse != "" {
						updateCloudflareDDNS(cfToken, zoneIDToUse, d, newIP)
					}
				}
			}
			return false
		}
		// 还没到最大次数，继续循环，等待 5 分钟
		addLog("info", "等待 5 分钟后进行下一次更换尝试...")
		time.Sleep(5 * time.Minute)
	}

	return true
}

// 从商家页面抓取并解析新公网 IP
func fetchNewIPFromMerchant(urlStr string) string {
	resp, err := http.Get(urlStr)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return extractIPFromHTML(string(bodyBytes))
}

// 正则提取合法公网 IP
func extractIPFromHTML(body string) string {
	re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	matches := re.FindAllString(body, -1)
	for _, match := range matches {
		ip := net.ParseIP(match)
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() {
			return match
		}
	}
	return ""
}

type CFDnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type CFDnsListResponse struct {
	Success bool          `json:"success"`
	Result  []CFDnsRecord `json:"result"`
}

type CFZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CFZonesResponse struct {
	Success bool     `json:"success"`
	Result  []CFZone `json:"result"`
}

func fetchCloudflareZones(token string) []CFZone {
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?per_page=100", nil)
	if err != nil {
		log.Printf("创建 CF Zones 请求失败: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求 CF Zones 失败: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var r CFZonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !r.Success {
		log.Printf("解析 CF Zones 失败: %v, success=%t", err, r.Success)
		return nil
	}
	return r.Result
}

func parseDomainsList(domainStr string) []string {
	var res []string
	parts := strings.Split(domainStr, ",")
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// 更新 Cloudflare DDNS 记录
func updateCloudflareDDNS(token, zoneID, domain, ip string) bool {
	// 1. 获取 DNS 记录 ID
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", zoneID, domain)
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		log.Printf("创建 CF 请求失败: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求 CF 获取记录失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	var listResp CFDnsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil || !listResp.Success || len(listResp.Result) == 0 {
		log.Printf("解析 CF 记录列表失败: %v, success=%t, len=%d", err, listResp.Success, len(listResp.Result))
		return false
	}

	recordID := listResp.Result[0].ID

	// 2. 更新 A 记录
	updateURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	payload := map[string]interface{}{
		"type":    "A",
		"name":    domain,
		"content": ip,
		"ttl":     60,
		"proxied": false,
	}
	payloadBytes, _ := json.Marshal(payload)

	req, err = http.NewRequest("PUT", updateURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建 CF 更新请求失败: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		log.Printf("请求 CF 更新记录失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	var updateResp struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		log.Printf("解析 CF 更新响应失败: %v", err)
		return false
	}

	return updateResp.Success
}

func lookupIPDirectly(domain string) ([]string, error) {
	// 使用 223.5.5.5 (阿里公共DNS) 或 1.1.1.1 (Cloudflare) 直接解析，绕过本地系统/路由器的缓存
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 2 * time.Second,
			}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		resolver1 := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 2 * time.Second,
				}
				return d.DialContext(ctx, "udp", "1.1.1.1:53")
			},
		}
		ctx1, cancel1 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel1()
		ips, err = resolver1.LookupIPAddr(ctx1, domain)
		if err != nil {
			return nil, err
		}
	}

	var res []string
	for _, ip := range ips {
		res = append(res, ip.IP.String())
	}
	return res, nil
}

// TCP 端口探测与主循环
func probeLoop() {
	failCount := 0
	dnsSyncAttempts := 0
	for {
		configMutex.RLock()
		domainStr := config.HinetDomain
		port := config.HinetPort
		interval := config.CheckIntervalSeconds
		autoChange := config.AutoChangeEnabled
		configMutex.RUnlock()

		lastCheck = time.Now()
		statusState = "checking"

		domains := parseDomainsList(domainStr)
		if len(domains) == 0 {
			statusState = "error"
			addLog("error", "未配置 Hinet 域名，跳过本次检测")
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}
		probeDomain := domains[0]

		// 1. 解析域名获取当前 IP（绕过本地缓存直接查询公共 DNS）
		ips, err := lookupIPDirectly(probeDomain)
		if err != nil {
			statusState = "error"
			addLog("error", fmt.Sprintf("域名 %s 解析失败: %v", probeDomain, err))
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}

		currentIP := ips[0]
		statusIP = currentIP

		// 检查 DNS 解析是否已和我们记录的最新 IP 同步
		configMutex.RLock()
		expectedIP := lastChangedIP
		configMutex.RUnlock()

		if expectedIP != "" && currentIP != expectedIP {
			dnsSyncAttempts++
			if dnsSyncAttempts < 30 { // 最多等待 5 分钟 (30 * 10s)
				addLog("warning", fmt.Sprintf("检测到域名 %s DNS 解析未同步：当前解析为 %s，预期为 %s。等待 DNS 缓存刷新 (%d/30)...", probeDomain, currentIP, expectedIP, dnsSyncAttempts))
				time.Sleep(10 * time.Second)
				continue
			} else {
				addLog("error", "DNS 解析同步超时（已等待 5 分钟），强制继续探测...")
				configMutex.Lock()
				lastChangedIP = "" // 清除期望，避免继续阻塞
				configMutex.Unlock()
				dnsSyncAttempts = 0
			}
		} else {
			dnsSyncAttempts = 0 // 同步成功，重置计数器
		}

		// 2. 进行 TCP 端口连接测试
		address := net.JoinHostPort(currentIP, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)

		if err != nil {
			// 连接失败，可能被墙或服务器宕机
			failCount++
			statusState = "blocked"
			addLog("error", fmt.Sprintf("TCP 探测失败 (%d/3): 无法连接到 %s (原因: %v)", failCount, address, err))

			if failCount >= 3 {
				addLog("error", "连续 3 次探测失败，判定 IP 已被墙或端口阻断！")
				if autoChange {
					if !lastFailedChangeTime.IsZero() && time.Since(lastFailedChangeTime) < 20*time.Minute {
						addLog("warning", fmt.Sprintf("IP自动更换目前处于 20 分钟冷却期内（已过去 %s），跳过本次更换以防止被限速或锁死。", time.Since(lastFailedChangeTime).Truncate(time.Second)))
					} else {
						if triggerChangeIP() {
							failCount = 0 // 重置计数器
							lastFailedChangeTime = time.Time{} // 重置冷却时间
						} else {
							lastFailedChangeTime = time.Now()
							addLog("error", "本轮 3 次 IP 更换已全部失败，可能由于服务宕机或端口填错。现已进入 20 分钟安全冷却期，期间不再自动触发更换。")
						}
					}
				} else {
					addLog("info", "自动更换 IP 功能已关闭，跳过更换。")
				}
			}
		} else {
			// 连接成功，网络正常
			conn.Close()
			if failCount > 0 {
				addLog("success", fmt.Sprintf("连接已恢复正常！共重试了 %d 次", failCount))
			}
			failCount = 0
			statusState = "online"
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func main() {
	loadConfig()
	addLog("info", "Hinet 监控服务已启动，正在初始化探测任务...")

	go probeLoop()

	// 注册 Web 路由
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/toggle", handleToggle)
	http.HandleFunc("/api/trigger", handleTrigger)
	http.HandleFunc("/api/save", handleSaveConfig)

	addLog("success", fmt.Sprintf("可视化控制台已运行在 http://0.0.0.0%s", config.ListenAddr))
	if err := http.ListenAndServe(config.ListenAddr, nil); err != nil {
		log.Fatalf("启动 Web 服务失败: %v", err)
	}
}

// Web 处理器：首页
func handleIndex(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	configMutex.RLock()
	defer configMutex.RUnlock()
	t.Execute(w, config)
}

// API: 获取状态数据
func handleStatus(w http.ResponseWriter, r *http.Request) {
	configMutex.RLock()
	defer configMutex.RUnlock()
	logsMutex.Lock()
	defer logsMutex.Unlock()

	data := map[string]interface{}{
		"ip":                  statusIP,
		"state":               statusState,
		"last_check":          lastCheck.Format(time.RFC3339),
		"auto_change_enabled": config.AutoChangeEnabled,
		"logs":                logs,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// API: 切换自动更换开关
func handleToggle(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	config.AutoChangeEnabled = !config.AutoChangeEnabled
	saveConfigNoLock()
	enabled := config.AutoChangeEnabled
	configMutex.Unlock()

	addLog("info", fmt.Sprintf("已手动切换自动更换 IP 开关为: %t", enabled))
	w.WriteHeader(http.StatusOK)
}

// API: 手动触发强制换 IP
func handleTrigger(w http.ResponseWriter, r *http.Request) {
	go triggerChangeIP()
	w.WriteHeader(http.StatusOK)
}

// API: 保存设置
func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newCfg Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configMutex.Lock()
	config.HinetDomain = newCfg.HinetDomain
	config.HinetPort = newCfg.HinetPort
	config.ChangeIPURL = newCfg.ChangeIPURL
	config.CheckIntervalSeconds = newCfg.CheckIntervalSeconds
	config.ListenAddr = newCfg.ListenAddr
	config.CFToken = newCfg.CFToken
	config.CFZoneID = newCfg.CFZoneID
	saveConfigNoLock()
	configMutex.Unlock()

	addLog("success", "监控参数配置已成功更新并保存。")
	w.WriteHeader(http.StatusOK)
}

// Embedded UI Frontend Template
const htmlTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hinet VPS 连通性监控与自动换IP控制台</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0d0e12;
            --card-bg: rgba(22, 24, 30, 0.8);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #e2e8f0;
            --text-muted: #94a3b8;
            --primary: #a855f7;
            --success: #10b981;
            --failed: #ef4444;
            --warning: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
            background-image: radial-gradient(circle at 10% 20%, rgba(168, 85, 247, 0.06) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
        }

        .container {
            width: 100%;
            max-width: 900px;
            display: grid;
            grid-template-columns: 1.2fr 1.8fr;
            gap: 24px;
        }

        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }
        }

        .left-col, .right-col {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .header h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a855f7, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 6px;
        }

        .header p {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            backdrop-filter: blur(20px);
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* 状态展示 */
        .status-display {
            display: flex;
            flex-direction: column;
            gap: 16px;
            align-items: center;
            text-align: center;
            padding: 10px 0;
        }

        .status-badge {
            width: 90px;
            height: 90px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.2rem;
            position: relative;
        }

        .status-badge::after {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            animation: pulse 2s infinite;
            opacity: 0.4;
        }

        .status-badge.online { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .status-badge.online::after { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0.2); }

        .status-badge.blocked { background: rgba(239, 68, 68, 0.15); color: var(--failed); }
        .status-badge.blocked::after { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0.2); }

        .status-badge.checking { background: rgba(168, 85, 247, 0.15); color: var(--primary); }
        .status-badge.checking::after { box-shadow: 0 0 0 10px rgba(168, 85, 247, 0.2); }

        .status-badge.error { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
        .status-badge.error::after { box-shadow: 0 0 0 10px rgba(245, 158, 11, 0.2); }

        .status-text {
            font-size: 1.4rem;
            font-weight: 700;
        }

        .status-details {
            width: 100%;
            margin-top: 10px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            border-top: 1px dashed var(--border-color);
            padding-top: 16px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
        }

        .detail-label {
            color: var(--text-muted);
        }

        .detail-val {
            font-weight: 600;
        }

        /* 按钮与开关 */
        .btn {
            width: 100%;
            background: linear-gradient(135deg, #a855f7, #7e22ce);
            color: white;
            border: none;
            padding: 12px;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(168, 85, 247, 0.2);
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(168, 85, 247, 0.3);
        }

        .btn-warning {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            box-shadow: 0 4px 15px rgba(245, 158, 11, 0.2);
        }

        .btn-warning:hover {
            box-shadow: 0 6px 20px rgba(245, 158, 11, 0.3);
        }

        /* Apple Switch */
        .switch {
            position: relative;
            display: inline-block;
            width: 46px;
            height: 24px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255,255,255,0.1);
            transition: .3s;
            border-radius: 24px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: var(--success);
        }

        input:checked + .slider:before {
            transform: translateX(22px);
        }

        /* 表单样式 */
        .form-group {
            margin-bottom: 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .form-group label {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: 600;
        }

        .form-control {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            border-radius: 10px;
            color: white;
            font-size: 0.95rem;
            width: 100%;
            transition: border-color 0.2s;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary);
        }

        /* 日志区域 */
        .logs-container {
            max-height: 480px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 10px;
            padding-right: 6px;
        }

        .logs-container::-webkit-scrollbar {
            width: 6px;
        }

        .logs-container::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        .log-item {
            padding: 12px;
            border-radius: 10px;
            border-left: 4px solid var(--primary);
            background: rgba(255,255,255,0.02);
            font-size: 0.85rem;
            line-height: 1.4;
        }

        .log-item.success { border-left-color: var(--success); background: rgba(16, 185, 129, 0.03); }
        .log-item.warning { border-left-color: var(--warning); background: rgba(245, 158, 11, 0.03); }
        .log-item.error { border-left-color: var(--failed); background: rgba(239, 68, 68, 0.03); }

        .log-meta {
            display: flex;
            justify-content: space-between;
            color: var(--text-muted);
            font-size: 0.75rem;
            margin-bottom: 4px;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(168, 85, 247, 0.3); }
            70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(168, 85, 247, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(168, 85, 247, 0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 左侧栏：状态展示 + 快速控制 -->
        <div class="left-col">
            <div class="header">
                <h1>Hinet 连通监控</h1>
                <p>实时 TCP 探测与自动防封换 IP 系统</p>
            </div>

            <!-- 状态卡片 -->
            <div class="card">
                <div class="card-title">系统当前状态</div>
                <div class="status-display">
                    <div class="status-badge checking" id="state-badge">⌛</div>
                    <div class="status-text" id="state-text">探测中</div>
                    <div class="status-details">
                        <div class="detail-row">
                            <span class="detail-label">当前公网 IP</span>
                            <span class="detail-val" id="ip-val">载入中...</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">最后一次检测</span>
                            <span class="detail-val" id="last-check-val">-</span>
                        </div>
                        <div class="detail-row" style="align-items: center; margin-top: 6px;">
                            <span class="detail-label">自动更换 IP</span>
                            <label class="switch">
                                <input type="checkbox" id="auto-change-toggle" onchange="toggleAutoChange()">
                                <span class="slider"></span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 手动操作卡片 -->
            <div class="card">
                <div class="card-title">快捷操作</div>
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <button class="btn" onclick="triggerCheck()">立即发起检测</button>
                    <button class="btn btn-warning" onclick="triggerChange()">强制更换公网 IP</button>
                </div>
            </div>
        </div>

        <!-- 右侧栏：参数设置 + 日志记录 -->
        <div class="right-col">
            <!-- 配置修改卡片 -->
            <div class="card">
                <div class="card-title">监控参数设置</div>
                <form id="config-form" onsubmit="saveConfig(event)">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                        <div class="form-group">
                            <label>Hinet 绑定域名 (DDNS，支持英文逗号分隔多个子域名)</label>
                            <input type="text" class="form-control" name="hinet_domain" value="{{.HinetDomain}}" required>
                        </div>
                        <div class="form-group">
                            <label>代理端口 (TCP 探测)</label>
                            <input type="number" class="form-control" name="hinet_port" value="{{.HinetPort}}" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>商家更换 IP 的 API 链接</label>
                        <input type="text" class="form-control" name="change_ip_url" value="{{.ChangeIPURL}}" required>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                        <div class="form-group">
                            <label>探测检测间隔 (秒)</label>
                            <input type="number" class="form-control" name="check_interval_seconds" value="{{.CheckIntervalSeconds}}" required>
                        </div>
                        <div class="form-group">
                            <label>Web 控制台监听端口</label>
                            <input type="text" class="form-control" name="listen_addr" value="{{.ListenAddr}}" required>
                        </div>
                    </div>
                    <div style="border-top: 1px solid rgba(255, 255, 255, 0.1); margin: 20px 0; padding-top: 20px;">
                        <h4 style="margin: 0 0 12px 0; color: var(--primary);">Cloudflare DDNS 联动 (可选)</h4>
                        <p style="font-size: 12px; color: var(--text-muted); margin: 0 0 16px 0;">配置后，换 IP 成功后会自动更新 Cloudflare 的 A 记录，无需 VPS 本地定时任务。</p>
                        <div class="form-group">
                            <label>Cloudflare API Token</label>
                            <input type="password" class="form-control" name="cf_token" value="{{.CFToken}}" placeholder="输入具有 DNS:Edit 权限的 Token">
                        </div>
                        <div class="form-group" style="margin-top: 12px;">
                            <label>Cloudflare Zone ID</label>
                            <input type="text" class="form-control" name="cf_zone_id" value="{{.CFZoneID}}" placeholder="输入域名所在的 Zone ID">
                        </div>
                    </div>
                    <button type="submit" class="btn" style="margin-top: 10px;">保存配置并应用</button>
                </form>
            </div>

            <!-- 日志卡片 -->
            <div class="card">
                <div class="card-title">系统日志</div>
                <div class="logs-container" id="logs-container">
                    <div style="color: var(--text-muted); text-align: center; padding: 20px;">暂无日志数据</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let logsMap = new Set();

        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();

                // 更新状态卡片
                document.getElementById('ip-val').innerText = data.ip || '未知';
                if (data.last_check) {
                    const checkTime = new Date(data.last_check);
                    if (checkTime.getFullYear() > 2000) {
                        document.getElementById('last-check-val').innerText = checkTime.toLocaleTimeString('zh-CN', { hour12: false });
                    } else {
                        document.getElementById('last-check-val').innerText = '-';
                    }
                } else {
                    document.getElementById('last-check-val').innerText = '-';
                }
                document.getElementById('auto-change-toggle').checked = data.auto_change_enabled;

                const badge = document.getElementById('state-badge');
                const stateText = document.getElementById('state-text');
                
                badge.className = 'status-badge ' + data.state;
                if (data.state === 'online') {
                    badge.innerText = '✓';
                    stateText.innerText = '网络畅通';
                    stateText.style.color = 'var(--success)';
                } else if (data.state === 'blocked') {
                    badge.innerText = '✗';
                    stateText.innerText = 'TCP 封锁/异常';
                    stateText.style.color = 'var(--failed)';
                } else if (data.state === 'checking') {
                    badge.innerText = '⌛';
                    stateText.innerText = '正在探测';
                    stateText.style.color = 'var(--primary)';
                } else {
                    badge.innerText = '⚠';
                    stateText.innerText = '网络故障';
                    stateText.style.color = 'var(--warning)';
                }

                // 更新日志
                const logsContainer = document.getElementById('logs-container');
                if (data.logs && data.logs.length > 0) {
                    logsContainer.innerHTML = data.logs.map(log => {
                        let logTime = log.timestamp;
                        try {
                            const d = new Date(log.timestamp);
                            if (d.getFullYear() > 2000) {
                                logTime = d.toLocaleString('zh-CN', { hour12: false });
                            }
                        } catch (e) {}
                        return '<div class="log-item ' + log.type + '">' +
                            '<div class="log-meta">' +
                                '<span class="log-time">' + logTime + '</span>' +
                                '<span class="log-type-tag">' + log.type.toUpperCase() + '</span>' +
                            '</div>' +
                            '<div class="log-body">' + log.message + '</div>' +
                        '</div>';
                    }).join('');
                } else {
                    logsContainer.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">暂无日志数据</div>';
                }
            } catch (err) {
                console.error("无法获取状态:", err);
            }
        }

        async function toggleAutoChange() {
            await fetch('/api/toggle', { method: 'POST' });
            fetchStatus();
        }

        async function triggerCheck() {
            // 简单轮询刷新
            fetchStatus();
        }

        async function triggerChange() {
            if (confirm("确定要强制重新拨号更换 IP 吗？此操作会导致网络中断约 20 秒。")) {
                await fetch('/api/trigger', { method: 'POST' });
                alert("已在后台提交换 IP 申请！");
                fetchStatus();
            }
        }

        async function saveConfig(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = {};
            formData.forEach((value, key) => {
                if (key === 'hinet_port' || key === 'check_interval_seconds') {
                    data[key] = parseInt(value, 10);
                } else {
                    data[key] = value;
                }
            });

            try {
                const res = await fetch('/api/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    alert("配置已成功保存！");
                    fetchStatus();
                } else {
                    alert("配置保存失败，请检查数据。");
                }
            } catch (err) {
                alert("网络错误，保存失败。");
            }
        }

        // 定时轮询
        fetchStatus();
        setInterval(fetchStatus, 3000);
    </script>
</body>
</html>
`
