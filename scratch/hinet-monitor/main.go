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
	ExternalCheckEnabled   bool   `json:"external_check_enabled"`   // 新增：是否启用外部第三方多地测活二次确认
	ExternalCheckURL       string `json:"external_check_url"`       // 新增：外部测活接口模版（支持 {ip} 和 {port} 变量）
	ExternalCheckKeyword   string `json:"external_check_keyword"`   // 新增：外部测活判断存活的成功关键字
	ExternalCheckTimeout   int    `json:"external_check_timeout"`   // 新增：外部测活请求超时时间（秒）
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
	discardedIP          string // 新增：记录被废弃替换的旧 IP，防止 DNS 缓存未刷新导致误拿旧 IP 测活

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
		HinetDomain:            "hinet.example.com",
		HinetPort:              443,
		ChangeIPURL:            "https://newip.lala.gg/hinetapi.php?type=change&lanip=10.92.2.14",
		CheckIntervalSeconds:   60,
		AutoChangeEnabled:      true,
		ListenAddr:             ":18080",
		CheckPort:              80, // 默认使用 80 端口自检
		WaitSecondsAfterChange: 90, // 默认换IP后等待 90 秒
		ExternalCheckEnabled:   true,
		ExternalCheckURL:       "https://v2.xxapi.cn/api/tcping?address={ip}&port={port}",
		ExternalCheckKeyword:   "ping",
		ExternalCheckTimeout:   8,
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
	if config.ExternalCheckTimeout <= 0 {
		config.ExternalCheckTimeout = 8
	}
	if config.ExternalCheckURL == "" || strings.Contains(config.ExternalCheckURL, "pearktrue") {
		// 自动平滑升级为稳定可用的国内官方开放测活接口
		config.ExternalCheckURL = "https://v2.xxapi.cn/api/tcping?address={ip}&port={port}"
		config.ExternalCheckKeyword = "ping"
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

// checkLocalInternetAlive 检测本机自身是否能正常访问国内互联网（排除本地断网导致的误切）
func checkLocalInternetAlive() bool {
	// 尝试向国内主流公共 DNS 的 53 端口发起快速 TCP 连接
	dnsServers := []string{"223.5.5.5:53", "119.29.29.29:53"}
	for _, srv := range dnsServers {
		conn, err := net.DialTimeout("tcp", srv, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// 外部探针返回结果三态枚举
const (
	ExtResultAlive = 1 // 目标存活（外部探针明确测试通过）
	ExtResultDead  = 2 // 目标不可达（外部探针正常运行，且明确检测到目标端口不通）
	ExtResultError = 3 // 探针自身故障（接口网络不通、DNS 解析失败、HTTP 5xx、超时等）
)

// checkExternalLiveness 通过外部第三方/多地接口复核目标 IP 与端口的连通性（方案 C）
func checkExternalLiveness(targetIP string, port int) (int, string) {
	configMutex.RLock()
	rawURL := config.ExternalCheckURL
	keyword := strings.TrimSpace(config.ExternalCheckKeyword)
	timeoutSec := config.ExternalCheckTimeout
	configMutex.RUnlock()

	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	if rawURL == "" {
		return ExtResultError, "未配置外部测活 API URL"
	}

	// 动态替换变量
	apiURL := strings.ReplaceAll(rawURL, "{ip}", targetIP)
	apiURL = strings.ReplaceAll(apiURL, "{port}", strconv.Itoa(port))

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return ExtResultError, fmt.Sprintf("构造请求失败: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HinetMonitor/2.0")

	resp, err := client.Do(req)
	if err != nil {
		// 铁律：探针自身网络错误或 DNS 失败，绝不能当成目标被封！
		return ExtResultError, fmt.Sprintf("调用外部接口失败或网络异常: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ExtResultError, fmt.Sprintf("外部探针返回异常状态码 %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return ExtResultError, fmt.Sprintf("读取外部接口响应失败: %v", err)
	}
	bodyStr := string(bodyBytes)

	// 如果指定了关键字，严格匹配关键字
	if keyword != "" {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
			return ExtResultAlive, fmt.Sprintf("成功匹配到关键字 [%s]", keyword)
		}
		brief := strings.ReplaceAll(strings.ReplaceAll(bodyStr, "\r", ""), "\n", " ")
		if len(brief) > 80 {
			brief = brief[:80] + "..."
		}
		return ExtResultDead, fmt.Sprintf("外部探针未检测到关键字 [%s] (返回: %s)", keyword, brief)
	}

	// 若未指定关键字，判断是否包含显式错误词
	lower := strings.ToLower(bodyStr)
	if strings.Contains(lower, "closed") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") || strings.Contains(lower, "timeout") || strings.Contains(lower, "连接失败") {
		return ExtResultDead, fmt.Sprintf("外部探针反馈连接失败: %s", bodyStr)
	}

	return ExtResultAlive, fmt.Sprintf("HTTP %d 接口成功响应", resp.StatusCode)
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

	zoneIDToUse := cfZoneID
	if cfToken != "" {
		zones := fetchCloudflareZones(cfToken)
		for _, z := range zones {
			if strings.HasSuffix(probeDomain, z.Name) {
				zoneIDToUse = z.ID
				break
			}
		}
	}

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
		var apiReturnedIP string
		if isNewAPI {
			addLog("info", "检测到新版 Hinet API，使用 GET 请求触发更换 IP...")
			resp, err := http.Get(changeURL)
			if err != nil {
				addLog("error", fmt.Sprintf("调用新版换 IP 接口失败: %v", err))
				sameIPCount++
				if sameIPCount >= maxTries {
					addLog("error", fmt.Sprintf("连续 %d 次调用接口失败或 IP 未发生变化，触发安全冷却", maxTries))
					return false
				}
				addLog("info", "等待 30 秒后重试...")
				time.Sleep(30 * time.Second)
				continue
			}
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			apiReturnedIP = extractIPFromHTML(string(bodyBytes))
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
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			apiReturnedIP = extractIPFromHTML(string(bodyBytes))
		}

		// 3. 混合测活：优先拿 API 的结果进行尝试，同时监听 CF 变化
		addLog("warning", fmt.Sprintf("已发送 IP 更换指令，开始混合轮询测活 (最长等待 %d 秒)...", waitSec))

		if apiReturnedIP != "" && apiReturnedIP != currentAttemptOldIP {
			addLog("info", fmt.Sprintf("商家 API 第一时间返回了新 IP: %s，我们将尝试对它测活，同时监听远端 DDNS...", apiReturnedIP))
		}

		newIP := ""
		isSuccess := false
		startTime := time.Now()
		checkAttempt := 0
		lastCfCheck := time.Now().Add(-10 * time.Second) // 确保第一次立即检查

		for time.Since(startTime) < time.Duration(waitSec)*time.Second {
			checkAttempt++
			targetIP := ""

			// 优先检查 CF 是否有更新（每 5 秒查一次即可，不用每次循环都查）
			if time.Since(lastCfCheck) >= 5*time.Second {
				lastCfCheck = time.Now()
				var resolvedIP string
				if cfToken != "" && zoneIDToUse != "" {
					resolvedIP = getCloudflareDDNS(cfToken, zoneIDToUse, probeDomain)
				} else {
					dnsIPs, err := lookupIPDirectly(probeDomain)
					if err == nil && len(dnsIPs) > 0 {
						for _, rIP := range dnsIPs {
							if rIP != currentAttemptOldIP && rIP != "" {
								resolvedIP = rIP
								break
							}
						}
					}
				}
				
				if resolvedIP != "" && resolvedIP != currentAttemptOldIP {
					// CF/DNS 上出现了新 IP，这是最真实的，覆盖掉 API 返回的 IP！
					if newIP != resolvedIP {
						addLog("success", fmt.Sprintf("检测到 Cloudflare (或 DNS) 已被更新，获取到绝对真实新 IP: %s，立即转向测活该 IP！", resolvedIP))
					}
					newIP = resolvedIP
				}
			}

			if newIP != "" {
				targetIP = newIP // CF 给了新 IP，最高优先级
			} else if apiReturnedIP != "" && apiReturnedIP != currentAttemptOldIP {
				targetIP = apiReturnedIP // CF 还没更新，先拿 API 返回的 IP 垫背试试
			}

			if targetIP != "" {
				address := net.JoinHostPort(targetIP, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", address, 3*time.Second)
				if err == nil {
					conn.Close()
					isSuccess = true
					newIP = targetIP
					break // 只要有一个能通，直接起飞！
				}
				if checkAttempt%3 == 1 { // 避免日志刷屏，每隔几次输出一次
					sourceLabel := "API 预分配"
					if targetIP == newIP {
						sourceLabel = "CF 权威"
					}
					addLog("warning", fmt.Sprintf("目标 IP [%s] %s TCP 探测等待上线中 (第 %d 次尝试): %v", sourceLabel, targetIP, checkAttempt, err))
				}
			} else {
				if checkAttempt%3 == 1 {
					addLog("warning", fmt.Sprintf("暂无新 IP 可测 (等待远端拨号响应中)，等待中 (第 %d 次尝试)...", checkAttempt))
				}
			}
			time.Sleep(3 * time.Second)
		}

		if !isSuccess {
			// 4. TCP 探测失败（超时）
			addLog("error", "在规定的时间内未能检测到有效的存活新 IP，判定拨号系统异常或被墙。")
			sameIPCount++
			if sameIPCount >= maxTries {
				addLog("error", fmt.Sprintf("连续 %d 次更换 IP 后均未测通，触发安全冷却期。", maxTries))
				return false
			}
			addLog("info", "等待 10 秒后进行下一次更换尝试...")
			time.Sleep(10 * time.Second)
			continue
		}

		// 成功获取到不同于旧 IP 的新 IP，重置 IP 未变化计数器
		sameIPCount = 0
		oldIP = newIP // 更新 oldIP 为当前最新获得的 IP，以便下一次尝试对比

		if isSuccess {
			addLog("success", fmt.Sprintf("TCP 自检通过！新 IP %s 确认可用上线！", newIP))

			configMutex.Lock()
			if currentAttemptOldIP != "" && currentAttemptOldIP != newIP {
				discardedIP = currentAttemptOldIP // 记录被淘汰废弃的旧 IP，防止后续从 DNS 查出旧 IP 误测
				addLog("info", fmt.Sprintf("已将旧 IP %s 记录为已废弃旧 IP，在域名记录生效前将自动忽略此旧 IP", discardedIP))
			}
			statusIP = newIP      // 提前更新状态 IP
			lastChangedIP = newIP // 记录期望的新 IP
			activeIP = newIP      // 更新当前确保存活的最新的公网 IP
			configMutex.Unlock()

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

			// （已移除强制同步 IP 以便 SSH 排查的代码，一切以远端 DDNS 为准）
			return false
		}
		// 判定被墙后，立即发起下一轮 IP 更换，只等待 5 秒防 API 频控！
		addLog("warning", "立即准备发起下一轮 IP 更换，等待 5 秒后继续...")
		time.Sleep(5 * time.Second)
	}

	return true
}

// (已废弃提取商家 IP 的逻辑，改为直接通过 CF 权威记录或 DNS 获取)

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

// (已删除 updateCloudflareDDNS，交由远端脚本处理)

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

func getCloudflareDDNS(token, zoneID, domain string) string {
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=A", zoneID, domain)
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var listResp CFDnsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil || !listResp.Success || len(listResp.Result) == 0 {
		return ""
	}

	return listResp.Result[0].Content
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

		configMutex.RLock()
		cfToken := config.CFToken
		cfZoneID := config.CFZoneID
		configMutex.RUnlock()

		zoneIDToUse := cfZoneID
		if cfToken != "" {
			zones := fetchCloudflareZones(cfToken)
			for _, z := range zones {
				if strings.HasSuffix(probeDomain, z.Name) {
					zoneIDToUse = z.ID
					break
				}
			}
		}

		// 1. 获取权威 IP：优先查询 CF 权威记录，否则使用公共 DNS 查询
		var currentIP string
		cfIP := ""
		if cfToken != "" && zoneIDToUse != "" {
			cfIP = getCloudflareDDNS(cfToken, zoneIDToUse, probeDomain)
		}

		if cfIP != "" {
			currentIP = cfIP
		} else {
			ips, err := lookupIPDirectly(probeDomain)
			if err != nil {
				statusState = "error"
				addLog("error", fmt.Sprintf("域名 %s 解析失败: %v", probeDomain, err))
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}
			currentIP = ips[0]
		}

		configMutex.Lock()
		if activeIP == "" {
			activeIP = currentIP
		}
		actIP := activeIP
		discIP := discardedIP
		expectedIP := lastChangedIP
		configMutex.Unlock()

		// 检查 DNS 解析是否已和我们记录的最新 IP 同步
		if expectedIP != "" {
			if currentIP == expectedIP {
				configMutex.Lock()
				lastChangedIP = "" // 匹配成功后，必须清空期望
				discardedIP = ""   // DNS 已成功同步为新 IP，清空废弃旧 IP 记录
				configMutex.Unlock()
				dnsSyncAttempts = 0
				addLog("success", fmt.Sprintf("域名 %s 记录已与预期最新 IP %s 成功同步！", probeDomain, currentIP))
			} else {
				dnsSyncAttempts++
				if dnsSyncAttempts < 30 { // 最多等待 5 分钟 (30 * 10s)
					addLog("warning", fmt.Sprintf("检测到域名 %s 记录未同步：当前为 %s，预期为 %s。等待刷新 (%d/30)...", probeDomain, currentIP, expectedIP, dnsSyncAttempts))
					time.Sleep(10 * time.Second)
					continue
				} else {
					addLog("error", "记录同步超时（已等待 5 分钟），解除等待继续探测...")
					configMutex.Lock()
					lastChangedIP = "" // 清除期望，避免继续阻塞
					configMutex.Unlock()
					dnsSyncAttempts = 0
				}
			}
		} else {
			dnsSyncAttempts = 0 // 同步成功，重置计数器
		}

		// 确定本次探测的目标 IP (detectIP)，坚决屏蔽已废弃旧 IP 与 DNS 滞后缓存干扰
		detectIP := currentIP
		if discIP != "" && currentIP == discIP {
			// DNS 解析出来的居然是刚才换掉的废弃旧 IP！
			if actIP != "" && actIP != discIP {
				detectIP = actIP
				addLog("warning", fmt.Sprintf("域名解析结果 (%s) 为刚换掉的废弃旧 IP (DNS尚未更新)，自动锁定最新可用新 IP (%s) 进行探测！", currentIP, actIP))
			}
		} else if actIP != "" && currentIP != actIP {
			// 解析出的 IP 与已知最新存活 IP 不一致，先快速探测已知存活 IP 是否还在工作
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(actIP, strconv.Itoa(port)), 2*time.Second)
			if err == nil {
				conn.Close()
				detectIP = actIP
				addLog("info", fmt.Sprintf("域名解析为 %s，但当前确认的有效新 IP %s 仍保持通畅，继续锁定该 IP 测活 (忽略滞后 DNS 解析)。", currentIP, actIP))
			} else {
				detectIP = currentIP
				if cfIP != "" {
					addLog("warning", fmt.Sprintf("检测到 Cloudflare 权威记录已更新为 %s，原可用 IP %s 已不通。以 CF 最新 IP 为准探测。", currentIP, actIP))
				} else {
					addLog("warning", fmt.Sprintf("域名解析已更新为 %s，原可用 IP %s 已不通。以最新解析 IP 为准探测。", currentIP, actIP))
				}
			}
		}

		configMutex.Lock()
		statusIP = detectIP
		configMutex.Unlock()

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

			addLog("error", fmt.Sprintf("本地 TCP 探测失败 (%d/3): 无法连接到 %s (原因: %v)", checkIdx, address, err))
			if checkIdx < 3 {
				time.Sleep(2 * time.Second)
			}
		}

		if !isAlive {
			// 新增防呆：如果探测失败且 detectIP != actIP，尝试回退探测原可用 IP
			if actIP != "" && detectIP != actIP {
				addLog("warning", fmt.Sprintf("目标 IP %s 探测失败，尝试对备选有效 IP %s 进行后备测活...", detectIP, actIP))
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(actIP, strconv.Itoa(port)), 5*time.Second)
				if err == nil {
					conn.Close()
					addLog("success", fmt.Sprintf("备选有效 IP %s 依然畅通！维持原有状态不变。", actIP))
					statusState = "online"
					time.Sleep(time.Duration(interval) * time.Second)
					continue
				}
				addLog("error", fmt.Sprintf("备选有效 IP %s 也已失效。", actIP))
			}

			// --- 【第 1 道守卫：本地断网保护】 ---
			if !checkLocalInternetAlive() {
				statusState = "network_down"
				addLog("error", "[本地网络断网保护] 检测到本地设备自身无法访问公网 (223.5.5.5:53 连接失败)，已安全阻止换 IP 操作，等待本地网络恢复...")
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}

			// --- 【第 2 道守卫：外部第三方多地测活二次确认 (方案 C)】 ---
			configMutex.RLock()
			extEnabled := config.ExternalCheckEnabled
			extURL := config.ExternalCheckURL
			configMutex.RUnlock()

			if extEnabled && extURL != "" {
				addLog("warning", fmt.Sprintf("本地探测 %s 失败，启动外部第三方异地探针复核连通性...", address))
				extStatus, extMsg := checkExternalLiveness(detectIP, port)
				if extStatus == ExtResultAlive {
					statusState = "online"
					addLog("success", fmt.Sprintf("[外部二次确认通过] 本地探测不通，但外部异地探针检测 %s 为畅通！(%s)。判定为本地单点运营商路由阻断，其他网络正常，坚决不换 IP！", address, extMsg))
					time.Sleep(time.Duration(interval) * time.Second)
					continue
				} else if extStatus == ExtResultError {
					// 核心防线：探针自身故障，绝不盲目换 IP！
					statusState = "probe_error"
					addLog("error", fmt.Sprintf("[外部探针自身故障] 无法连接到外部测活接口 (%s)！缺乏有效第三方复核，为防误杀已安全终止换 IP，维持现有 IP 不变。", extMsg))
					time.Sleep(time.Duration(interval) * time.Second)
					continue
				} else {
					// ExtResultDead: 外部探针正常运行且明确告知目标不通！
					addLog("error", fmt.Sprintf("[双重确认均失败] 本地探测不通，且外部异地探针复核同样无法连通 %s (%s)！确认目标被阻断或服务离线。", address, extMsg))
				}
			}

			configMutex.RLock()
			autoChangeEnabled := autoChange
			configMutex.RUnlock()

			statusState = "blocked"
			addLog("error", "本地与外部探针均无法连通，判定当前 IP 已失效！")

			configMutex.RLock()
			graceWaitSec := config.WaitSecondsAfterChange
			if graceWaitSec <= 0 {
				graceWaitSec = 90
			}
			configMutex.RUnlock()

			// 动态宽限期机制，防止 Hinet 自然重新拨号且 DDNS 尚未同步的真空期导致误判
			gracePeriodPassed := false
			if autoChangeEnabled {
				addLog("warning", fmt.Sprintf("为防止 Hinet 自然更换 IP 导致 DDNS 未及时同步，进入 %d 秒宽限期观察远端记录与连通性...", graceWaitSec))
				graceStartTime := time.Now()
				lastLoggedIP := currentIP
				for time.Since(graceStartTime) < time.Duration(graceWaitSec)*time.Second {
					time.Sleep(5 * time.Second)
					
					testIP := detectIP // 默认继续测活失败的那个
					if cfToken != "" && zoneIDToUse != "" {
						newCfIP := getCloudflareDDNS(cfToken, zoneIDToUse, probeDomain)
						if newCfIP != "" {
							testIP = newCfIP
							if newCfIP != lastLoggedIP {
								addLog("info", fmt.Sprintf("宽限期内检测到 CF 权威记录变更为 %s！正在尝试测活...", newCfIP))
								lastLoggedIP = newCfIP
							}
						}
					}
					
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(testIP, strconv.Itoa(port)), 3*time.Second)
					if err == nil {
						conn.Close()
						addLog("success", fmt.Sprintf("宽限期内测活成功 (IP: %s)！确认为自然恢复或自然换 IP 成功，取消主动换 IP 计划。", testIP))
						configMutex.Lock()
						activeIP = testIP
						lastChangedIP = testIP
						statusIP = testIP
						configMutex.Unlock()
						statusState = "online"
						gracePeriodPassed = true
						break
					}
				}

				if !gracePeriodPassed {
					addLog("error", fmt.Sprintf("%d 秒宽限期结束，依然未检测到存活状态，准备执行主动更换 IP 指令。", graceWaitSec))
				}
			}

			if gracePeriodPassed {
				// 在宽限期内已恢复，直接进入下一个循环
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}

			if autoChangeEnabled {
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
			if actIP != detectIP {
				configMutex.Lock()
				activeIP = detectIP
				configMutex.Unlock()
				addLog("success", fmt.Sprintf("确认新记录 IP %s 可用，已更新内部状态。", detectIP))
			}
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
		"ip":                     statusIP,
		"state":                  statusState,
		"last_check":             lastCheck.Format(time.RFC3339),
		"auto_change_enabled":    config.AutoChangeEnabled,
		"external_check_enabled": config.ExternalCheckEnabled,
		"active_ip":              activeIP,
		"discarded_ip":           discardedIP,
		"logs":                   logs,
		"monitor_statuses":       monitorStatuses,
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
		actIP := activeIP
		discIP := discardedIP
		configMutex.Unlock()

		detectIP := currentIP
		if discIP != "" && currentIP == discIP {
			if actIP != "" && actIP != discIP {
				detectIP = actIP
				addLog("warning", fmt.Sprintf("手动探测：域名解析结果 (%s) 为废弃旧 IP，自动锁定最新可用新 IP (%s) 探测！", currentIP, actIP))
			}
		} else if actIP != "" && currentIP != actIP {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(actIP, strconv.Itoa(port)), 2*time.Second)
			if err == nil {
				conn.Close()
				detectIP = actIP
				addLog("info", fmt.Sprintf("手动探测：域名解析为 %s，但当前确认的有效新 IP %s 仍保持通畅，优先使用有效 IP 测活！", currentIP, actIP))
			} else {
				detectIP = currentIP
			}
		}

		// 2. TCP 探测
		address := net.JoinHostPort(detectIP, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			statusState = "blocked"
			addLog("error", fmt.Sprintf("手动探测失败：无法连接到 %s (原因: %v)", address, err))

			// 辅助诊断：本地网络断网检查与外部探针检查
			if !checkLocalInternetAlive() {
				addLog("error", "手动探测辅助诊断：检测到您本地设备自身无法访问公网 (223.5.5.5:53 失败)，说明当前机器断网！")
			} else {
				configMutex.RLock()
				extEnabled := config.ExternalCheckEnabled
				extURL := config.ExternalCheckURL
				configMutex.RUnlock()
				if extEnabled && extURL != "" {
					addLog("warning", fmt.Sprintf("本地探测 %s 不通，正在尝试外部第三方探针复核...", address))
					extStatus, extMsg := checkExternalLiveness(detectIP, port)
					if extStatus == ExtResultAlive {
						addLog("success", fmt.Sprintf("外部探针复核结果：外部节点可成功连通 %s！(%s)。确认为本地单点网络波动！", address, extMsg))
					} else if extStatus == ExtResultError {
						addLog("warning", fmt.Sprintf("外部探针辅助诊断：外部测活接口自身不可用 (%s)。请检查接口网络配置！", extMsg))
					} else {
						addLog("error", fmt.Sprintf("外部探针复核结果：外部节点同样无法连通 %s (%s)！", address, extMsg))
					}
				}
			}
		} else {
			conn.Close()
			statusState = "online"
			addLog("success", fmt.Sprintf("手动探测成功：连接 %s 通畅，当前测试 IP: %s", address, detectIP))
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
	config.ExternalCheckEnabled = newCfg.ExternalCheckEnabled
	config.ExternalCheckURL = newCfg.ExternalCheckURL
	config.ExternalCheckKeyword = newCfg.ExternalCheckKeyword
	config.ExternalCheckTimeout = newCfg.ExternalCheckTimeout
	saveConfigNoLock()
	configMutex.Unlock()

	addLog("success", "监控参数配置已成功更新并保存（外部测活与防旧IP配置已热生效）。")
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

        /* 优雅子卡片面板与快捷标签 */
        .sub-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 14px;
            padding: 16px 18px;
            margin: 18px 0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }

        .sub-card.cf {
            border-color: rgba(168, 85, 247, 0.2);
        }

        .sub-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .sub-card-title {
            font-size: 0.92rem;
            font-weight: 700;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .sub-card-title.purple {
            color: #c084fc;
        }

        .sub-card-desc {
            font-size: 0.78rem;
            color: var(--text-muted);
            line-height: 1.5;
            margin-bottom: 12px;
            background: rgba(56, 189, 248, 0.05);
            border-left: 3px solid #38bdf8;
            padding: 6px 10px;
            border-radius: 0 6px 6px 0;
        }

        .sub-card-desc.purple {
            background: rgba(168, 85, 247, 0.05);
            border-left-color: #a855f7;
        }

        .preset-container {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
            flex-wrap: wrap;
        }

        .preset-label {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .preset-chip {
            background: rgba(56, 189, 248, 0.1);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.25);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }

        .preset-chip:hover {
            background: rgba(56, 189, 248, 0.22);
            border-color: rgba(56, 189, 248, 0.5);
            transform: translateY(-1px);
        }

        .preset-chip.purple {
            background: rgba(168, 85, 247, 0.1);
            color: #c084fc;
            border-color: rgba(168, 85, 247, 0.25);
        }

        .preset-chip.purple:hover {
            background: rgba(168, 85, 247, 0.22);
            border-color: rgba(168, 85, 247, 0.5);
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
                            <label>宽限观察与等待上线 (秒)</label>
                            <input type="number" class="form-control" name="wait_seconds_after_change" value="{{.WaitSecondsAfterChange}}" required>
                        </div>
                        <div class="form-group">
                            <label>Web 控制台监听端口</label>
                            <input type="text" class="form-control" name="listen_addr" value="{{.ListenAddr}}" required>
                        </div>
                    </div>
                    <!-- 外部多地测活二次确认 (方案 C) 专属精致卡片 -->
                    <div class="sub-card">
                        <div class="sub-card-header">
                            <div class="sub-card-title">
                                <span>🌐 外部多地测活二次确认 (方案 C，防单点误切)</span>
                            </div>
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 0.82rem; font-weight: 600; color: #38bdf8;">
                                <input type="checkbox" name="external_check_enabled" value="true" {{if .ExternalCheckEnabled}}checked{{end}}> 启用二次确认
                            </label>
                        </div>
                        <div class="sub-card-desc">
                            当本地探测失败时，先由本地守卫检查公网连通性，再调用外部异地 API 复核。外部能通则判定为本地单点网络波动，<strong>坚决不换 IP</strong>；若外部探针自身故障或超时，自动进入<strong>防误杀保护</strong>，绝不乱切！
                        </div>
                        <div class="form-group" style="margin-bottom: 12px;">
                            <label>外部测活 API URL 模板 (支持 <code style="color:#38bdf8">{ip}</code> 和 <code style="color:#38bdf8">{port}</code> 占位符)</label>
                            <input type="text" class="form-control" id="external_check_url" name="external_check_url" value="{{.ExternalCheckURL}}" placeholder="https://v2.xxapi.cn/api/tcping?address={ip}&port={port}">
                        </div>
                        <div class="form-row-2">
                            <div class="form-group">
                                <label>成功判断关键字 (留空则以 HTTP 200 为准)</label>
                                <input type="text" class="form-control" id="external_check_keyword" name="external_check_keyword" value="{{.ExternalCheckKeyword}}" placeholder="例如 ping 或 open">
                            </div>
                            <div class="form-group">
                                <label>请求超时时间 (秒)</label>
                                <input type="number" class="form-control" name="external_check_timeout" value="{{.ExternalCheckTimeout}}" min="3" max="30">
                            </div>
                        </div>
                        <div class="preset-container">
                            <span class="preset-label">快捷填充模板:</span>
                            <button type="button" class="preset-chip" onclick="fillPreset('xxapi')">⚡ 国内高可用公网 TCPing (推荐免配置)</button>
                            <button type="button" class="preset-chip purple" onclick="fillPreset('serverless')">☁️ 自建云函数/国内VPS</button>
                        </div>
                    </div>

                    <!-- Cloudflare DDNS 联动专属精致卡片 -->
                    <div class="sub-card cf">
                        <div class="sub-card-header">
                            <div class="sub-card-title purple">
                                <span>☁️ Cloudflare DDNS 联动 (可选)</span>
                            </div>
                        </div>
                        <div class="sub-card-desc purple">
                            配置后换 IP 成功会自动更新 Cloudflare 的 A 记录。未配置时将完全依赖远端机器的自带 DDNS。
                        </div>
                        <div class="form-group" style="margin-bottom: 12px;">
                            <label>Cloudflare API Token</label>
                            <input type="password" class="form-control" name="cf_token" value="{{.CFToken}}" placeholder="输入具有 DNS:Edit 权限的 Token">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
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

        function fillPreset(type) {
            const urlInput = document.getElementById('external_check_url');
            const kwInput = document.getElementById('external_check_keyword');
            if (type === 'xxapi') {
                urlInput.value = 'https://v2.xxapi.cn/api/tcping?address={ip}&port={port}';
                kwInput.value = 'ping';
            } else if (type === 'serverless') {
                urlInput.value = 'https://你的云函数或国内VPS/ping?ip={ip}&port={port}';
                kwInput.value = 'open';
            }
        }

        async function saveConfig(e) {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            const data = {};
            formData.forEach((value, key) => {
                if (key === 'hinet_port' || key === 'check_interval_seconds' || key === 'check_port' || key === 'wait_seconds_after_change' || key === 'monitor_interval_sec' || key === 'external_check_timeout') {
                    data[key] = value ? parseInt(value, 10) : 0;
                } else {
                    data[key] = value;
                }
            });

            // 获取 Checkbox 状态
            const extCheckEl = form.querySelector('input[name="external_check_enabled"]');
            data['external_check_enabled'] = extCheckEl ? extCheckEl.checked : false;

            try {
                const res = await fetch('/api/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    alert("配置已成功保存！外部测活及防旧IP配置已立即生效。");
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
