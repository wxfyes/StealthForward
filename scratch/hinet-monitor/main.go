package main

import (
	"context"
	"crypto/tls"
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
	HinetDomain            string `json:"hinet_domain"`
	HinetPort              int    `json:"hinet_port"`
	ChangeIPURL            string `json:"change_ip_url"`
	CheckIntervalSeconds   int    `json:"check_interval_seconds"`
	AutoChangeEnabled      bool   `json:"auto_change_enabled"`
	ListenAddr             string `json:"listen_addr"`
	CFToken                string `json:"cf_token"`
	CFZoneID               string `json:"cf_zone_id"`
	CheckPort              int    `json:"check_port"` // 新增：自检探测端口
	WaitSecondsAfterChange int    `json:"wait_seconds_after_change"` // 新增：换IP后等待拨号时间（秒）
	MonitorDomains         string `json:"monitor_domains"`
	MonitorWebhook         string `json:"monitor_webhook"`
	MonitorIntervalSec     int    `json:"monitor_interval_sec"`
	MonitorProxy           string `json:"monitor_proxy"` // 新增：TG报警代理 URL
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"` // "info", "success", "warning", "error"
	Message   string `json:"message"`
}

// MonitorStatus 域名国内直连拦截状态
type MonitorStatus struct {
	Domain     string    `json:"domain"`
	Port       int       `json:"port"`
	DnsStatus  string    `json:"dns_status"`
	TcpStatus  string    `json:"tcp_status"`
	ResolveIPs []string  `json:"resolve_ips"`
	CheckedAt  time.Time `json:"checked_at"`
}

// Global State
var (
	config               Config
	configMutex          sync.RWMutex
	logs                 []LogEntry
	logsMutex            sync.Mutex
	statusIP             string
	statusState          string = "online"
	lastCheck            time.Time
	configFile           = "config.json"
	lastChangedIP        string // 新增：最后一次更换成功的新 IP
	lastFailedChangeTime time.Time // 新增：最后一次更换全部失败的时间
	activeIP             string // 新增：当前已确认存活最新的公网 IP，防止 DNS 缓存抖动误判

	monitorStatuses      []MonitorStatus
	monitorStatusesMutex sync.RWMutex

	// GFW 常见的黑洞投毒 IP
	gfwPoisonedIPs = map[string]bool{
		"37.61.54.158":  true,
		"46.82.174.69":  true,
		"59.24.3.173":   true,
		"64.233.189.10": true,
		"74.125.127.102":true,
		"78.16.49.15":   true,
		"93.46.8.89":    true,
		"93.46.8.90":    true,
		"203.98.7.65":   true,
		"216.58.203.14": true,
		"243.185.187.39":true,
		"8.7.198.46":    true,
	}
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
		ChangeIPURL:          "https://newip.lala.gg/hinetapi.php?type=change&lanip=10.92.2.14",
		CheckIntervalSeconds: 60,
		AutoChangeEnabled:    true,
		ListenAddr:           ":18080",
		CheckPort:            80, // 默认使用 80 端口自检
		WaitSecondsAfterChange: 90, // 默认换IP后等待 90 秒
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		saveConfigNoLock()
	}

	if config.WaitSecondsAfterChange <= 0 {
		config.WaitSecondsAfterChange = 90
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

func triggerChangeIP() bool {
	configMutex.RLock()
	changeURL := config.ChangeIPURL
	cfToken := config.CFToken
	cfZoneID := config.CFZoneID
	domainStr := config.HinetDomain
	port := config.CheckPort
	if port <= 0 {
		port = config.HinetPort
	}
	waitSec := config.WaitSecondsAfterChange
	if waitSec <= 0 {
		waitSec = 90
	}
	configMutex.RUnlock()

	domains := parseDomainsList(domainStr)
	if len(domains) == 0 {
		addLog("error", "未配置 Hinet 域名，无法确定当前 IP")
		return false
	}
	probeDomain := domains[0]

	// 1. 获取当前域名的公网 IP 作为 oldIP
	var oldIP string
	ips, err := lookupIPDirectly(probeDomain)
	if err == nil && len(ips) > 0 {
		oldIP = ips[0]
	}
	addLog("info", fmt.Sprintf("开始触发更换 IP 流程，当前域名 IP 为: %s", oldIP))

	maxTries := 10   // 增加最大尝试次数至 10 次，允许在遇到被墙 IP 时多次重试
	sameIPCount := 0 // 记录 IP 没有发生变化的次数 (接口/拨号故障)

	for attempt := 1; attempt <= maxTries; attempt++ {
		addLog("warning", fmt.Sprintf("开始调用商家接口申请更换公网 IP (第 %d/%d 次尝试)...", attempt, maxTries))

		// 记录本次尝试前的 IP
		currentAttemptOldIP := oldIP

		// 2. 调用 API 触发更换
		isNewAPI := strings.Contains(changeURL, "hinetapi.php") || strings.Contains(changeURL, "type=change")
		if isNewAPI {
			addLog("info", "检测到新版 Hinet API，使用 GET 请求触发更换 IP...")
			resp, err := http.Get(changeURL)
			if err != nil {
				addLog("error", fmt.Sprintf("调用新版换 IP 接口失败: %v", err))
				sameIPCount++
				if sameIPCount >= 3 {
					addLog("error", "连续 3 次调用接口失败或 IP 未发生变化，触发安全冷却")
					return false
				}
				addLog("info", "等待 30 秒后重试...")
				time.Sleep(30 * time.Second)
				continue
			}
			resp.Body.Close()
		} else {
			resp, err := http.PostForm(changeURL, url.Values{"change_ip": {}})
			if err != nil {
				addLog("error", fmt.Sprintf("调用旧版换 IP 接口失败: %v", err))
				sameIPCount++
				if sameIPCount >= 3 {
					addLog("error", "连续 3 次调用接口失败或 IP 未发生变化，触发安全冷却")
					return false
				}
				addLog("info", "等待 30 秒后重试...")
				time.Sleep(30 * time.Second)
				continue
			}
			resp.Body.Close()
		}

		// 3. 等待并轮询获取真正的新 IP
		addLog("warning", fmt.Sprintf("已发送 IP 更换指令，开始轮询等待新 IP 分配并同步 (最长等待 %d 秒)...", waitSec))

		newIP := ""
		startTime := time.Now()

		// 构造一个查询 status 的 URL，解析 changeURL 动态生成同 host 下的 /214higl.php 接口，安全查看当前 IP
		statusURL := "https://newip.lala.gg/214higl.php"
		u, err := url.Parse(changeURL)
		if err == nil {
			statusURL = fmt.Sprintf("%s://%s/214higl.php", u.Scheme, u.Host)
		}

		for {
			// A. 尝试通过 DNS 解析获取 IP (若 VPS 上运行了 DDNS 脚本，域名解析会更新)
			dnsIPs, err := lookupIPDirectly(probeDomain)
			if err == nil && len(dnsIPs) > 0 {
				resolvedIP := dnsIPs[0]
				if resolvedIP != currentAttemptOldIP && resolvedIP != "" {
					newIP = resolvedIP
					addLog("success", fmt.Sprintf("检测到 DNS 已同步更新，获取到新 IP: %s", newIP))
					break
				}
			}

			// B. 尝试通过商家 API 查询获取 IP (只在 statusURL 不含 type=change 时请求，防止重复触发)
			if !strings.Contains(statusURL, "type=change") {
				merchantIP := fetchNewIPFromMerchant(statusURL)
				if merchantIP != "" && merchantIP != currentAttemptOldIP {
					newIP = merchantIP
					addLog("success", fmt.Sprintf("检测到商家接口返回新 IP: %s", newIP))
					break
				}
			}

			// 检查是否超时
			if time.Since(startTime) > time.Duration(waitSec)*time.Second {
				break
			}
			time.Sleep(5 * time.Second)
		}

		// 4. 判断获取到的 IP 是否有效且发生了改变
		if newIP == "" || newIP == currentAttemptOldIP {
			addLog("error", "未能获取到新的公网 IP (IP 未发生变化或获取超时)。")
			sameIPCount++
			if sameIPCount >= 3 {
				addLog("error", "连续 3 次更换 IP 后公网 IP 未发生变化，判定拨号系统异常，进入安全冷却期。")
				return false
			}
			addLog("info", "等待 10 秒后进行下一次更换尝试...")
			time.Sleep(10 * time.Second)
			continue
		}

		// 成功获取到不同于旧 IP 的新 IP，重置 IP 未变化计数器
		sameIPCount = 0
		oldIP = newIP // 更新 oldIP 为当前最新获得的 IP，以便下一次尝试对比

		addLog("info", fmt.Sprintf("开始对新公网 IP %s 进行 TCP 可用性自检...", newIP))

		// 5. 对新 IP 进行 3 次快速 TCP 探测
		address := net.JoinHostPort(newIP, strconv.Itoa(port))
		isSuccess := false
		for checkAttempt := 1; checkAttempt <= 3; checkAttempt++ {
			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err == nil {
				conn.Close()
				isSuccess = true
				break
			}
			addLog("warning", fmt.Sprintf("新 IP %s 第 %d/3 次 TCP 探测失败 (端口 %d 不通): %v", newIP, checkAttempt, port, err))
			if checkAttempt < 3 {
				time.Sleep(2 * time.Second)
			}
		}

		if isSuccess {
			addLog("success", fmt.Sprintf("TCP 自检通过！新 IP %s 确认可用，开始同步到 Cloudflare...", newIP))

			configMutex.Lock()
			statusIP = newIP      // 提前更新状态 IP
			lastChangedIP = newIP // 记录期望的新 IP
			activeIP = newIP      // 更新当前确保存活的最新的公网 IP
			configMutex.Unlock()

			// 同步 Cloudflare DDNS (如果配置了)
			if cfToken != "" {
				domainsList := parseDomainsList(domainStr)
				addLog("info", fmt.Sprintf("正在同步新 IP %s 到 Cloudflare (共有 %d 个域名)...", newIP, len(domainsList)))
				zones := fetchCloudflareZones(cfToken)
				successCount := 0
				for _, d := range domainsList {
					zoneIDToUse := cfZoneID
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
				if successCount == len(domainsList) {
					addLog("success", "所有绑定的域名 DNS 解析均已成功同步更新。")
				} else {
					addLog("warning", fmt.Sprintf("域名同步更新完成：成功 %d 个，失败 %d 个", successCount, len(domainsList)-successCount))
				}
			} else {
				addLog("info", "未配置 Cloudflare API 参数，跳过 DNS 自动更新。")
			}
			return true
		}

		// TCP 探测失败，说明 IP 不可用（被墙）
		addLog("error", fmt.Sprintf("新 IP %s 连续 3 次 TCP 探测均失败，判定该 IP 不可用（被墙）。", newIP))
		if attempt == maxTries {
			addLog("error", fmt.Sprintf("已连续更换 %d 次 IP & TCP 自检全部失败！可能是您的 VPS 服务端程序已崩溃，或者端口配置错误，请登录 VPS 检查。", maxTries))
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
		// 判定被墙后，立即发起下一轮 IP 更换，只等待 5 秒防 API 频控！
		addLog("warning", "立即准备发起下一轮 IP 更换，等待 5 秒后继续...")
		time.Sleep(5 * time.Second)
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
	r := strings.NewReplacer("\r\n", ",", "\n", ",", " ", ",", "，", ",", "\t", ",")
	normalized := r.Replace(domainStr)
	var res []string
	parts := strings.Split(normalized, ",")
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

func lookupIPDirectlyInternal(domain string) ([]string, error) {
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

func lookupIPDirectly(domain string) ([]string, error) {
	type result struct {
		ips []string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ips, err := lookupIPDirectlyInternal(domain)
		ch <- result{ips, err}
	}()

	select {
	case res := <-ch:
		return res.ips, res.err
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("DNS lookup timeout after 5 seconds")
	}
}

// TCP 端口探测与主循环
func probeLoop() {
	dnsSyncAttempts := 0
	for {
		configMutex.RLock()
		domainStr := config.HinetDomain
		port := config.CheckPort
		if port <= 0 {
			port = config.HinetPort
		}
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

		configMutex.Lock()
		if activeIP == "" {
			activeIP = currentIP
		}
		configMutex.Unlock()

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
			if expectedIP != "" {
				configMutex.Lock()
				lastChangedIP = "" // 匹配成功后，必须清空期望，防止常规轮询重复执行无谓对比和提示
				configMutex.Unlock()
				addLog("success", fmt.Sprintf("域名 %s DNS 解析已与最新 IP %s 成功同步！", probeDomain, currentIP))
			}
		}

		detectIP := currentIP
		configMutex.RLock()
		actIP := activeIP
		configMutex.RUnlock()
		if actIP != "" && currentIP != actIP {
			addLog("warning", fmt.Sprintf("域名解析结果为 %s，与确认可用 IP %s 不一致，可能处于 DNS 缓存抖动中。将使用 %s 进行本次健康探测以防误判。", currentIP, actIP, actIP))
			detectIP = actIP
		}

		// 2. 进行 TCP 端口连接测试 (一旦失败，立即在 6 秒内连续快速探测 3 次复核，防止网络偶发抖动导致误判，大幅缩短断网响应时间)
		address := net.JoinHostPort(detectIP, strconv.Itoa(port))
		isAlive := false

		for checkIdx := 1; checkIdx <= 3; checkIdx++ {
			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err == nil {
				conn.Close()
				isAlive = true
				break
			}

			addLog("error", fmt.Sprintf("TCP 探测失败 (%d/3): 无法连接到 %s (原因: %v)", checkIdx, address, err))
			if checkIdx < 3 {
				time.Sleep(2 * time.Second)
			}
		}

		if !isAlive {
			statusState = "blocked"
			addLog("error", "连续 3 次快速探测均失败，判定当前 IP 已被墙或端口阻断！")
			if autoChange {
				if !lastFailedChangeTime.IsZero() && time.Since(lastFailedChangeTime) < 5*time.Minute {
					addLog("warning", fmt.Sprintf("IP自动更换目前处于 5 分钟冷却期内（已过去 %s），跳过本次更换以防止被限速或锁死。", time.Since(lastFailedChangeTime).Truncate(time.Second)))
				} else {
					if triggerChangeIP() {
						lastFailedChangeTime = time.Time{} // 重置冷却时间
					} else {
						lastFailedChangeTime = time.Now()
						addLog("error", "本轮 IP 更换已全部失败，可能由于服务宕机、连续未变或端口填错。现已进入 5 分钟安全冷却期，期间不再自动触发更换。")
					}
				}
			} else {
				addLog("info", "自动更换 IP 功能已关闭，跳过更换。")
			}
		} else {
			// 连接成功，网络正常
			statusState = "online"
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

// checkOriginLiveness 绕过国内 GFW 拦截直接向真实海外源站探测网站健康度和证书
// 支持传入普通域名（例如 "google.com"）或完整网站（例如 "https://google.com"）
func checkOriginLiveness(target string, defaultPort int) string {
	scheme := "https"
	domain := target
	port := defaultPort

	if strings.HasPrefix(target, "https://") {
		scheme = "https"
		domain = strings.TrimPrefix(target, "https://")
		port = 443
	} else if strings.HasPrefix(target, "http://") {
		scheme = "http"
		domain = strings.TrimPrefix(target, "http://")
		port = 80
	}

	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if strings.Contains(domain, ":") {
		subParts := strings.Split(domain, ":")
		domain = subParts[0]
		pVal, err := strconv.Atoi(subParts[1])
		if err == nil {
			port = pVal
		}
	}

	// 1. 获取该域名的 IP，避开国内 DNS 污染。优先使用阿里 DNS 探测。
	ips, err := lookupDNSWithServer(domain, "223.5.5.5")
	targetIP := domain // 默认直接使用域名直连，这样在 OpenWrt 开启科学分流时能自动走代理访问！
	if err == nil && len(ips) > 0 {
		// 检查解析出的 IP 是否被污染
		isPoisoned := false
		for _, ip := range ips {
			if gfwPoisonedIPs[ip] {
				isPoisoned = true
				break
			}
		}
		if !isPoisoned {
			targetIP = ips[0]
		} else {
			// 如果被污染，尝试从 1.1.1.1 干净 DNS 获取真实海外 IP
			cleanIps, err1 := lookupDNSWithServer(domain, "1.1.1.1")
			if err1 == nil && len(cleanIps) > 0 {
				targetIP = cleanIps[0]
			}
		}
	}

	// 2. 建立不附带 SNI (ServerName) 的 TLS 握手，以防被 GFW 的 SNI 重置审查拦截
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "", // 留空！这是绕过 SNI 拦截的关键！
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
	}

	urlStr := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(targetIP, strconv.Itoa(port)))

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "构造探测失败"
	}

	req.Host = domain

	resp, err := client.Do(req)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "timeout") {
			return "源站超时(可能宕机或IP阻断)"
		}
		return "源站连接拒绝(可能未启动)"
	}
	defer resp.Body.Close()

	certStr := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		days := int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
		if days <= 0 {
			certStr = ", ❌证书过期"
		} else if days < 7 {
			certStr = fmt.Sprintf(", ⚠证书剩%d天", days)
		} else {
			certStr = fmt.Sprintf(", 证书剩%d天", days)
		}
	}

	if resp.StatusCode >= 500 {
		return fmt.Sprintf("源站5xx(HTTP %d%s)", resp.StatusCode, certStr)
	}
	return fmt.Sprintf("正常(HTTP %d%s)", resp.StatusCode, certStr)
}

// checkDomainGfw 探测单个监控目标（支持 GFW 域名污染与阻断测试、纯 IP TCP 测试、HTTP/HTTPS 网站测活、TLS 证书有效期检测）
func checkDomainGfw(target string) MonitorStatus {
	// 默认初始化状态，Domain 存储展示用名字
	status := MonitorStatus{
		Domain:    target,
		Port:      0,
		CheckedAt: time.Now(),
	}

	isHTTP := strings.HasPrefix(target, "http://")
	isHTTPS := strings.HasPrefix(target, "https://")
	
	cleanDomainOrIP := target
	if isHTTPS {
		cleanDomainOrIP = strings.TrimPrefix(target, "https://")
		status.Port = 443
	} else if isHTTP {
		cleanDomainOrIP = strings.TrimPrefix(target, "http://")
		status.Port = 80
	}

	if idx := strings.Index(cleanDomainOrIP, "/"); idx != -1 {
		cleanDomainOrIP = cleanDomainOrIP[:idx]
	}
	
	port := status.Port
	if strings.Contains(cleanDomainOrIP, ":") {
		subParts := strings.Split(cleanDomainOrIP, ":")
		cleanDomainOrIP = subParts[0]
		pVal, err := strconv.Atoi(subParts[1])
		if err == nil {
			port = pVal
		}
	}
	if port == 0 {
		port = 443
	}
	status.Port = port

	isIP := net.ParseIP(cleanDomainOrIP) != nil

	if isIP {
		status.DnsStatus = "无需解析(IP)"
		status.ResolveIPs = []string{cleanDomainOrIP}

		if isHTTP || isHTTPS {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   4 * time.Second,
			}
			resp, err := client.Get(target)
			if err != nil {
				status.TcpStatus = "❌ 网站超时 (IP连接失败)"
				return status
			}
			defer resp.Body.Close()
			
			certStr := ""
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				days := int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
				certStr = fmt.Sprintf(" (证书剩%d天)", days)
			}
			status.TcpStatus = fmt.Sprintf("正常 (HTTP %d%s)", resp.StatusCode, certStr)
		} else {
			address := net.JoinHostPort(cleanDomainOrIP, strconv.Itoa(port))
			dialer := net.Dialer{Timeout: 3 * time.Second}
			rawConn, err := dialer.Dial("tcp", address)
			if err != nil {
				status.TcpStatus = "❌ 连接失败"
				return status
			}
			rawConn.Close()
			status.TcpStatus = "正常"
		}
		return status
	}

	ips, err := lookupDNSWithServer(cleanDomainOrIP, "223.5.5.5")
	if err != nil || len(ips) == 0 {
		status.DnsStatus = "解析失败"
		status.TcpStatus = "未知"
		return status
	}
	status.ResolveIPs = ips

	isPoisoned := false
	for _, ip := range ips {
		if gfwPoisonedIPs[ip] {
			isPoisoned = true
			break
		}
	}
	if isPoisoned {
		status.DnsStatus = "污染(被墙)"
		liveness := checkOriginLiveness(target, port)
		status.TcpStatus = "⚠️ 被墙 (" + liveness + ")"
		return status
	}
	status.DnsStatus = "正常"

	if isHTTP || isHTTPS {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   4 * time.Second,
		}

		resp, err := client.Get(target)
		if err != nil {
			liveness := checkOriginLiveness(target, port)
			if strings.Contains(liveness, "正常") {
				status.TcpStatus = "⚠️ 阻断 (" + liveness + ")"
			} else {
				status.TcpStatus = "❌ 网站超时 (" + liveness + ")"
			}
			return status
		}
		defer resp.Body.Close()

		certStr := ""
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			days := int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
			if days <= 0 {
				certStr = " (❌证书已过期)"
			} else if days < 7 {
				certStr = fmt.Sprintf(" (⚠证书剩%d天)", days)
			} else {
				certStr = fmt.Sprintf(" (证书剩%d天)", days)
			}
		}

		if resp.StatusCode >= 500 {
			status.TcpStatus = fmt.Sprintf("❌ 服务异常 (HTTP %d%s)", resp.StatusCode, certStr)
		} else {
			status.TcpStatus = fmt.Sprintf("正常 (HTTP %d%s)", resp.StatusCode, certStr)
		}
		return status
	}

	address := net.JoinHostPort(ips[0], strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 3 * time.Second}
	rawConn, err := dialer.Dial("tcp", address)
	if err != nil {
		liveness := checkOriginLiveness(cleanDomainOrIP, port)
		status.TcpStatus = "❌ 阻断 (" + liveness + ")"
		return status
	}
	defer rawConn.Close()

	// 1. 如果是 80 端口，发送普通 HTTP GET 探测状态码以检测 CDN 521 等报错
	if port == 80 {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://" + cleanDomainOrIP)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 500 {
				status.TcpStatus = fmt.Sprintf("❌ 服务异常 (HTTP %d)", resp.StatusCode)
				return status
			}
		}
		status.TcpStatus = "正常"
		return status
	}

	// 2. 如果是 443 端口，进行 TLS 握手并验证 HTTP 状态码
	if port == 443 {
		tlsConfig := &tls.Config{
			ServerName:         cleanDomainOrIP,
			InsecureSkipVerify: true,
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
		
		err = tlsConn.Handshake()
		if err != nil {
			liveness := checkOriginLiveness(cleanDomainOrIP, port)
			status.TcpStatus = "❌ 阻断 (" + liveness + ")"
		} else {
			certs := tlsConn.ConnectionState().PeerCertificates
			certStr := ""
			if len(certs) > 0 {
				days := int(time.Until(certs[0].NotAfter).Hours() / 24)
				if days <= 0 {
					certStr = " (❌证书已过期)"
				} else if days < 7 {
					certStr = fmt.Sprintf(" (⚠证书剩%d天)", days)
				} else {
					certStr = fmt.Sprintf(" (证书剩%d天)", days)
				}
			}
			
			// 向网站节点发送 GET 请求，以识别 CDN 521/502 等源站宕机报错
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				Timeout:   3 * time.Second,
			}
			resp, err := client.Get("https://" + cleanDomainOrIP)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 500 {
					status.TcpStatus = fmt.Sprintf("❌ 服务异常 (HTTP %d%s)", resp.StatusCode, certStr)
					return status
				}
			}
			
			status.TcpStatus = "正常" + certStr
		}
		return status
	}

	// 3. 其他普通端口的 TCP 直连通畅判定
	status.TcpStatus = "正常"
	return status
}

// lookupDNSWithServer 使用指定 DNS 服务器解析域名，绕过本地缓存
func lookupDNSWithServer(domain, dnsServer string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 2 * time.Second,
			}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dnsServer, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ip := range ips {
		res = append(res, ip.IP.String())
	}
	return res, nil
}

// triggerWebhook 发送报警 Webhook 或 Telegram 消息
func triggerWebhook(webhookURL, domain string, port int, dnsStatus, tcpStatus string) {
	isTG := strings.Contains(webhookURL, "api.telegram.org")
	var finalURL string
	if isTG {
		msg := fmt.Sprintf("⚠️【监控告警】\n目标: %s\nDNS 状态: %s\n连通状态: %s\n时间: %s", 
			domain, dnsStatus, tcpStatus, time.Now().Format("2006-01-02 15:04:05"))
		if !strings.Contains(webhookURL, "text=") {
			escapedMsg := url.QueryEscape(msg)
			if strings.Contains(webhookURL, "?") {
				finalURL = webhookURL + "&text=" + escapedMsg
			} else {
				finalURL = webhookURL + "?text=" + escapedMsg
			}
		} else {
			finalURL = webhookURL
		}
	} else {
		finalURL = webhookURL
	}

	configMutex.RLock()
	proxyStr := config.MonitorProxy
	configMutex.RUnlock()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyStr != "" {
		proxyURL, err := url.Parse(proxyStr)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	var resp *http.Response
	var err error

	if isTG {
		resp, err = client.Get(finalURL)
	} else {
		payload := fmt.Sprintf(`{"text":"⚠️【域名直连连通性监控告警】\n域名: %s\nDNS 状态: %s\n连通状态: %s"}`, domain, dnsStatus, tcpStatus)
		resp, err = client.Post(finalURL, "application/json", strings.NewReader(payload))
	}

	if err != nil {
		log.Printf("[监控警告] 发送告警通知失败: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[监控通知] 已成功触发告警 Webhook，目标: %s", domain)
}

// runMonitorCheckInternal 核心探测逻辑：由定时器和 API 同步复用
func runMonitorCheckInternal() {
	configMutex.RLock()
	domainListStr := config.MonitorDomains
	webhookURL := config.MonitorWebhook
	configMutex.RUnlock()

	targets := parseDomainsList(domainListStr)
	if len(targets) == 0 {
		monitorStatusesMutex.Lock()
		monitorStatuses = nil
		monitorStatusesMutex.Unlock()
		return
	}

	var wg sync.WaitGroup
	results := make([]MonitorStatus, len(targets))

	for idx, target := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			results[i] = checkDomainGfw(t)
		}(idx, target)
	}
	wg.Wait()

	monitorStatusesMutex.Lock()
	monitorStatuses = results
	monitorStatusesMutex.Unlock()

	// 检查是否有异常并发送报警通知
	if webhookURL != "" {
		for _, status := range results {
			if strings.Contains(status.DnsStatus, "失败") || 
				strings.Contains(status.DnsStatus, "污染") || 
				strings.Contains(status.TcpStatus, "❌") || 
				strings.Contains(status.TcpStatus, "超时") || 
				strings.Contains(status.TcpStatus, "重置") || 
				strings.Contains(status.TcpStatus, "拒绝") ||
				strings.Contains(status.TcpStatus, "失败") {
				// 触发异步告警
				go triggerWebhook(webhookURL, status.Domain, status.Port, status.DnsStatus, status.TcpStatus)
			}
		}
	}
}

// monitorLoop 多域名直连监控守护协程
func monitorLoop() {
	for {
		configMutex.RLock()
		interval := config.MonitorIntervalSec
		configMutex.RUnlock()

		if interval <= 0 {
			interval = 300
		}

		runMonitorCheckInternal()
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

// API: 手动触发直连域名监控检测
func handleMonitorCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 启动同步阻塞探测以确保返回时状态为最新
	runMonitorCheckInternal()
	w.WriteHeader(http.StatusOK)
}

// API: 重启程序本身
func handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addLog("warning", "已接收到 Web 控制台的重启指令，程序即将在 1 秒后自动退出并由守护程序/服务重新拉起...")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))

	go func() {
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}

func main() {
	loadConfig()
	addLog("info", "Hinet 监控服务已启动，正在初始化探测任务...")

	go probeLoop()
	go monitorLoop()

	// 注册 Web 路由
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/monitor", handleMonitorIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/toggle", handleToggle)
	http.HandleFunc("/api/trigger", handleTrigger)
	http.HandleFunc("/api/check", handleCheck)
	http.HandleFunc("/api/save", handleSaveConfig)
	http.HandleFunc("/api/monitor/check", handleMonitorCheck)
	http.HandleFunc("/api/restart", handleRestart)

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

// Web 处理器：监控页
func handleMonitorIndex(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("monitor").Parse(monitorHtmlTemplate)
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
	monitorStatusesMutex.RLock()
	defer monitorStatusesMutex.RUnlock()

	data := map[string]interface{}{
		"ip":                  statusIP,
		"state":               statusState,
		"last_check":          lastCheck.Format(time.RFC3339),
		"auto_change_enabled": config.AutoChangeEnabled,
		"logs":                logs,
		"monitor_statuses":    monitorStatuses,
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

// API: 手动立即检测连通性
func handleCheck(w http.ResponseWriter, r *http.Request) {
	go func() {
		configMutex.RLock()
		domainStr := config.HinetDomain
		port := config.CheckPort
		if port <= 0 {
			port = config.HinetPort
		}
		configMutex.RUnlock()

		addLog("info", "手动触发连通性检测中...")

		// 1. 获取当前域名的公网 IP
		domains := parseDomainsList(domainStr)
		if len(domains) == 0 {
			addLog("error", "手动探测失败：未配置绑定域名")
			return
		}
		probeDomain := domains[0]
		ips, err := lookupIPDirectly(probeDomain)
		if err != nil || len(ips) == 0 {
			addLog("error", fmt.Sprintf("手动探测：域名 %s 解析失败: %v", probeDomain, err))
			return
		}
		currentIP := ips[0]

		configMutex.Lock()
		if activeIP == "" {
			activeIP = currentIP
		}
		configMutex.Unlock()

		detectIP := currentIP
		configMutex.RLock()
		actIP := activeIP
		configMutex.RUnlock()
		if actIP != "" && currentIP != actIP {
			addLog("warning", fmt.Sprintf("域名解析结果为 %s，与确认可用 IP %s 不一致，可能处于 DNS 缓存抖动中。将使用 %s 进行本次探测以防误判。", currentIP, actIP, actIP))
			detectIP = actIP
		}

		// 2. TCP 探测
		address := net.JoinHostPort(detectIP, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			statusState = "blocked"
			addLog("error", fmt.Sprintf("手动探测失败：无法连接到 %s (原因: %v)", address, err))
		} else {
			conn.Close()
			statusState = "online"
			addLog("success", fmt.Sprintf("手动探测成功：连接 %s 通畅，当前公网 IP: %s", address, currentIP))
		}
		lastCheck = time.Now()
	}()
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
	config.CheckPort = newCfg.CheckPort
	config.ChangeIPURL = newCfg.ChangeIPURL
	config.CheckIntervalSeconds = newCfg.CheckIntervalSeconds
	config.WaitSecondsAfterChange = newCfg.WaitSecondsAfterChange
	config.ListenAddr = newCfg.ListenAddr
	config.CFToken = newCfg.CFToken
	config.CFZoneID = newCfg.CFZoneID
	config.MonitorDomains = newCfg.MonitorDomains
	config.MonitorWebhook = newCfg.MonitorWebhook
	config.MonitorIntervalSec = newCfg.MonitorIntervalSec
	config.MonitorProxy = newCfg.MonitorProxy
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

        .form-row-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }

        .form-row-3 {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 16px;
        }

        @media (max-width: 768px) {
            body {
                padding: 16px 12px;
            }
            .container {
                grid-template-columns: 1fr;
            }
            .card {
                padding: 16px;
            }
            .form-row-2, .form-row-3 {
                grid-template-columns: 1fr;
                gap: 12px;
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

        .btn-danger {
            background: linear-gradient(135deg, #ef4444, #b91c1c);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.2);
        }

        .btn-danger:hover {
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.3);
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

        /* 导航选项卡 */
        .nav-container {
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            width: 100%;
            grid-column: span 2;
        }
        .nav-btn {
            flex: 1;
            text-align: center;
            padding: 14px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-muted);
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            backdrop-filter: blur(20px);
        }
        .nav-btn:hover {
            color: var(--text-color);
            border-color: rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.05);
        }
        .nav-btn.active {
            color: white;
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.2), rgba(126, 34, 206, 0.2));
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.15);
        }
        
        @media (max-width: 768px) {
            .nav-container {
                flex-direction: column;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav-container">
            <a href="/" class="nav-btn active">💻 Hinet 拨号控制台</a>
            <a href="/monitor" class="nav-btn">🛡️ 多域名直连与源站监控</a>
        </div>
        
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
                    <button class="btn btn-danger" onclick="triggerRestart()">重启监控程序</button>
                </div>
            </div>

        </div>

        <!-- 右侧栏：参数设置 + 日志记录 -->
        <div class="right-col">
            <!-- 配置修改卡片 -->
            <div class="card">
                <div class="card-title">监控参数设置</div>
                <form id="config-form" onsubmit="saveConfig(event)">
                    <!-- 隐藏提交多域名直连监控配置，防止被覆盖清空 -->
                    <input type="hidden" name="monitor_domains" value="{{.MonitorDomains}}">
                    <input type="hidden" name="monitor_webhook" value="{{.MonitorWebhook}}">
                    <input type="hidden" name="monitor_interval_sec" value="{{.MonitorIntervalSec}}">
                    <input type="hidden" name="monitor_proxy" value="{{.MonitorProxy}}">
                    <div class="form-group">
                        <label>Hinet 绑定域名 (DDNS，支持英文逗号分隔多个子域名)</label>
                        <input type="text" class="form-control" name="hinet_domain" value="{{.HinetDomain}}" required>
                    </div>
                    <div class="form-row-2">
                        <div class="form-group">
                            <label>业务代理端口 (中转端口)</label>
                            <input type="number" class="form-control" name="hinet_port" value="{{.HinetPort}}" required>
                        </div>
                        <div class="form-group">
                            <label>自检探测端口 (TCP，常用如 80 或 22；留空代表与代理端口相同)</label>
                            <input type="number" class="form-control" name="check_port" value="{{.CheckPort}}">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>商家更换 IP 的 API 链接</label>
                        <input type="text" class="form-control" name="change_ip_url" value="{{.ChangeIPURL}}" required>
                    </div>
                    <div class="form-row-3">
                        <div class="form-group">
                            <label>探测检测间隔 (秒)</label>
                            <input type="number" class="form-control" name="check_interval_seconds" value="{{.CheckIntervalSeconds}}" required>
                        </div>
                        <div class="form-group">
                            <label>换IP后等待上线 (秒)</label>
                            <input type="number" class="form-control" name="wait_seconds_after_change" value="{{.WaitSecondsAfterChange}}" required>
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
            await fetch('/api/check', { method: 'POST' });
            fetchStatus();
        }



        async function triggerChange() {
            if (confirm("确定要强制重新拨号更换 IP 吗？此操作会导致网络中断约 20 秒。")) {
                await fetch('/api/trigger', { method: 'POST' });
                alert("已在后台提交换 IP 申请！");
                fetchStatus();
            }
        }

        async function triggerRestart() {
            if (confirm("确定要重启监控程序本身吗？")) {
                try {
                    const res = await fetch('/api/restart', { method: 'POST' });
                    if (res.ok) {
                        alert("已发送重启指令！程序将在 1 秒后退出，稍后请刷新页面重新连接。");
                    } else {
                        alert("发送重启指令失败！");
                    }
                } catch (e) {
                    alert("指令已发送，程序正在重启中，请稍后手动刷新网页。");
                }
                fetchStatus();
            }
        }

        async function saveConfig(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = {};
            formData.forEach((value, key) => {
                if (key === 'hinet_port' || key === 'check_interval_seconds' || key === 'check_port' || key === 'wait_seconds_after_change' || key === 'monitor_interval_sec') {
                    data[key] = value ? parseInt(value, 10) : 0;
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

// Embedded UI Monitor Page Template
const monitorHtmlTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>域名直连拦截与网站健康度监控</title>
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

        .container-wide {
            width: 100%;
            max-width: 1000px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* 导航选项卡 */
        .nav-container {
            display: flex;
            gap: 16px;
            width: 100%;
        }
        .nav-btn {
            flex: 1;
            text-align: center;
            padding: 14px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-muted);
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            backdrop-filter: blur(20px);
        }
        .nav-btn:hover {
            color: var(--text-color);
            border-color: rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.05);
        }
        .nav-btn.active {
            color: white;
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.2), rgba(126, 34, 206, 0.2));
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.15);
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

        /* 按钮与表单 */
        .btn {
            background: linear-gradient(135deg, #a855f7, #7e22ce);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 10px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(168, 85, 247, 0.2);
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(168, 85, 247, 0.3);
        }

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

        /* 宽表格样式 */
        .monitor-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            table-layout: fixed;
        }

        .monitor-table th, .monitor-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .monitor-table th {
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
        }

        .monitor-table td {
            font-size: 0.9rem;
        }

        /* 列宽规划 */
        .monitor-table th:nth-child(1), .monitor-table td:nth-child(1) { width: 30%; max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .monitor-table th:nth-child(2), .monitor-table td:nth-child(2) { width: 25%; max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .monitor-table th:nth-child(3), .monitor-table td:nth-child(3) { width: 15%; }
        .monitor-table th:nth-child(4), .monitor-table td:nth-child(4) { width: 30%; }

        .status-badge-small {
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
        }

        .status-badge-small.success { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .status-badge-small.failed { background: rgba(239, 68, 68, 0.15); color: var(--failed); }
        .status-badge-small.warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); }

        .split-layout {
            display: grid;
            grid-template-columns: 1.2fr 1.8fr;
            gap: 24px;
        }

        @media (max-width: 768px) {
            body {
                padding: 16px 12px;
            }
            .split-layout {
                grid-template-columns: 1fr;
            }
            .nav-container {
                flex-direction: column;
                gap: 10px;
            }
            .card {
                padding: 16px;
            }
        }

        /* 日志区域 */
        .logs-container {
            max-height: 380px;
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
        .domain-link {
            color: var(--primary) !important;
            text-decoration: none;
            font-weight: 600;
            border-bottom: 1px dashed var(--primary);
            transition: all 0.3s ease;
            word-break: break-all;
        }
        .domain-link:hover {
            color: white !important;
            border-bottom-color: white !important;
        }
    </style>
</head>
<body>
    <div class="container-wide">
        <div class="nav-container">
            <a href="/" class="nav-btn">💻 Hinet 拨号控制台</a>
            <a href="/monitor" class="nav-btn active">🛡️ 多域名直连与源站监控</a>
        </div>

        <div class="header">
            <h1>多域名国内直连与源站监控</h1>
            <p>定时检测直连 GFW 污染与阻断，源站宕机与 Nginx 测活，自动抓取并提醒 TLS 证书剩余天数</p>
        </div>

        <!-- 监控表格 -->
        <div class="card">
            <div class="card-title">
                <span>直连拦截与健康状态</span>
                <button class="btn" id="btn-monitor-check" onclick="triggerMonitorCheck()">立即检测</button>
            </div>
            <div style="overflow-x: auto;">
                <table class="monitor-table">
                    <thead>
                        <tr>
                            <th>域名 / 网站</th>
                            <th>解析出 IP</th>
                            <th>DNS 解析</th>
                            <th>国内直连 TCP / 源站生存状态</th>
                        </tr>
                    </thead>
                    <tbody id="monitor-tbody">
                        <tr>
                            <td colspan="4" style="color: var(--text-muted); text-align: center; padding: 20px;">暂无监控数据</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- 下方配置与日志 -->
        <div class="split-layout">
            <div class="card">
                <div class="card-title">监控参数设置</div>
                <form id="config-form" onsubmit="saveConfig(event)">
                    <!-- 隐藏提交 Hinet VPS 拨号配置，防止被覆盖清空 -->
                    <input type="hidden" name="hinet_domain" value="{{.HinetDomain}}">
                    <input type="hidden" name="hinet_port" value="{{.HinetPort}}">
                    <input type="hidden" name="check_port" value="{{.CheckPort}}">
                    <input type="hidden" name="change_ip_url" value="{{.ChangeIPURL}}">
                    <input type="hidden" name="check_interval_seconds" value="{{.CheckIntervalSeconds}}">
                    <input type="hidden" name="wait_seconds_after_change" value="{{.WaitSecondsAfterChange}}">
                    <input type="hidden" name="listen_addr" value="{{.ListenAddr}}">
                    <input type="hidden" name="cf_token" value="{{.CFToken}}">
                    <input type="hidden" name="cf_zone_id" value="{{.CFZoneID}}">

                    <div class="form-group">
                        <label>监控目标 (支持空格/逗号/换行分隔，可输入 IP、域名:端口 或 http(s) 网站)</label>
                        <textarea class="form-control" name="monitor_domains" rows="6" placeholder="例如: www.baidu.com:443 (可测证书)&#10;https://www.baidu.com (可测网站与证书)&#10;https://www.google.com (测试被墙测活)&#10;127.0.0.1:18080" style="resize: vertical; font-family: monospace;">{{.MonitorDomains}}</textarea>
                    </div>
                    <div class="form-group">
                        <label>报警 Webhook / TG 机器人发送接口</label>
                        <input type="text" class="form-control" name="monitor_webhook" value="{{.MonitorWebhook}}" placeholder="支持自定义 Webhook 或者 Telegram Bot 发送接口">
                    </div>
                    <div class="form-group">
                        <label>TG 报警代理 URL (可选，支持 socks5:// 或 http://)</label>
                        <input type="text" class="form-control" name="monitor_proxy" value="{{.MonitorProxy}}" placeholder="例如: socks5://127.0.0.1:1080 或 http://127.0.0.1:1089">
                        <span style="font-size: 0.75rem; color: var(--text-muted); margin-top: 2px;">
                            当国内无法连接 Telegram 接口时，可配置本地 Socks5 或 HTTP 代理（软路由科学上网暴露的代理端口）
                        </span>
                    </div>
                    <div class="form-group">
                        <label>定时探测间隔 (秒)</label>
                        <input type="number" class="form-control" name="monitor_interval_sec" value="{{.MonitorIntervalSec}}" placeholder="默认 300 秒">
                    </div>
                    <button type="submit" class="btn" style="margin-top: 10px; width: 100%;">保存配置并应用</button>
                </form>
            </div>

            <div class="card">
                <div class="card-title">监控运行日志</div>
                <div class="logs-container" id="logs-container">
                    <div style="color: var(--text-muted); text-align: center; padding: 20px;">暂无日志数据</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();

                // 1. 更新多域名直连状态表格
                const monitorTbody = document.getElementById('monitor-tbody');
                if (data.monitor_statuses && data.monitor_statuses.length > 0) {
                    monitorTbody.innerHTML = data.monitor_statuses.map(status => {
                        let dnsClass = status.dns_status === '正常' || status.dns_status === '网站监控' || status.dns_status === '无需解析(IP)' ? 'success' : 'failed';
                        let tcpClass = status.tcp_status === '正常' || status.tcp_status.indexOf('正常') === 0 ? 'success' : (status.tcp_status.indexOf('❌') !== -1 ? 'failed' : 'warning');
                        
                        let ipsStr = '-';
                        let fullIpsStr = '';
                        if (status.resolve_ips && status.resolve_ips.length > 0) {
                            fullIpsStr = status.resolve_ips.join(', ');
                            let rawIp = status.resolve_ips[0];
                            if (rawIp.length > 15) {
                                ipsStr = rawIp.substring(0, 8) + '...' + rawIp.substring(rawIp.length - 4);
                            } else {
                                ipsStr = rawIp;
                            }
                        }

                        let displayName = status.domain.replace(/^https?:\/\//, '');
                        if (status.port > 0 && status.domain.indexOf(':') === -1) {
                            displayName = displayName + ':' + status.port;
                        }

                        let targetUrl = status.domain;
                        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                            targetUrl = 'https://' + targetUrl;
                        }

                        return '<tr>' +
                            '<td title="点击跳转到该网站: ' + targetUrl + '">' +
                            '<a href="' + targetUrl + '" target="_blank" class="domain-link">' + 
                            displayName + '</a></td>' +
                            '<td style="color: var(--text-muted); font-size: 0.85rem;" title="' + fullIpsStr + '">' + ipsStr + '</td>' +
                            '<td><span class="status-badge-small ' + dnsClass + '">' + status.dns_status + '</span></td>' +
                            '<td><span class="status-badge-small ' + tcpClass + '">' + status.tcp_status + '</span></td>' +
                        '</tr>';
                    }).join('');
                } else {
                    monitorTbody.innerHTML = '<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 20px;">暂无监控数据</td></tr>';
                }

                // 2. 更新运行日志
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

        async function triggerMonitorCheck() {
            const btn = document.getElementById('btn-monitor-check');
            const originalText = btn.innerText;
            btn.innerText = "检测中...";
            btn.disabled = true;
            try {
                await fetch('/api/monitor/check', { method: 'POST' });
                setTimeout(async () => {
                    await fetchStatus();
                    btn.innerText = originalText;
                    btn.disabled = false;
                }, 1500);
            } catch (err) {
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }

        async function saveConfig(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = {};
            formData.forEach((value, key) => {
                if (key === 'hinet_port' || key === 'check_interval_seconds' || key === 'check_port' || key === 'wait_seconds_after_change' || key === 'monitor_interval_sec') {
                    data[key] = value ? parseInt(value, 10) : 0;
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
