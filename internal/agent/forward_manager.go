package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/wangn9900/StealthForward/internal/models"
)

type PortForwardInstance struct {
	Rule     models.PortForward
	Cmd      *exec.Cmd
	StopChan chan struct{}
}

type ForwardManager struct {
	mu         sync.RWMutex
	instances  map[uint]*PortForwardInstance // 记录本地正在运行的转发实例 (Key: RuleID)
	lastConfig []models.PortForward          // 记录上次同步到的规则列表
	traffic    map[uint]models.TrafficStat   // 本地缓存的累计流量 (由 iptables 读出)
	lastBytes  map[uint]models.TrafficStat   // 上一次成功读取的 iptables 流量字节数，用于计算增量
	nodeID     int
	localDir   string
}

var (
	// iptables 流量匹配正则 (匹配 -m comment --comment "stealth_pf_in_12" 这类规则)
	pfInRegex  = regexp.MustCompile(`\s*(\d+)\s+\d+\s+.*\s+dpt:(\d+)\s+/\*\s+stealth_pf_in_(\d+)\s+\*/`)
	pfOutRegex = regexp.MustCompile(`\s*(\d+)\s+\d+\s+.*\s+spt:(\d+)\s+/\*\s+stealth_pf_out_(\d+)\s+\*/`)
)

func NewForwardManager(nodeID int, localDir string) *ForwardManager {
	fm := &ForwardManager{
		instances: make(map[uint]*PortForwardInstance),
		traffic:   make(map[uint]models.TrafficStat),
		lastBytes: make(map[uint]models.TrafficStat),
		nodeID:    nodeID,
		localDir:  localDir,
	}

	// 启动时确保二进制文件就绪
	fm.EnsureBinaries()
	// 清理本地所有历史残留的端口转发进程和 iptables 规则 (防端口冲突自愈)
	fm.CleanResiduals()

	// 启动温和的定时读取 iptables 流量任务 (10秒一次，避免频繁 fork 导致爆 CPU/内存)
	go fm.collectTrafficLoop()

	return fm
}

// EnsureBinaries 检查并安装 realm / gost 二进制
func (fm *ForwardManager) EnsureBinaries() {
	if runtime.GOOS == "windows" {
		return
	}

	bins := []string{"realm", "gost"}
	for _, bin := range bins {
		path := filepath.Join("/usr/local/bin", bin)
		if _, err := os.Stat(path); err == nil {
			continue
		}

		log.Printf("[Forward] 二进制 %s 缺失，正在尝试自动安装...", bin)
		arch := "amd64"
		if runtime.GOARCH == "arm64" {
			arch = "arm64"
		}

		var downloadCmd string
		if bin == "realm" {
			downloadCmd = fmt.Sprintf("curl -L https://github.com/zhboner/realm/releases/latest/download/realm-x86_64-unknown-linux-gnu.tar.gz | tar -xz -C /tmp && mv /tmp/realm %s && chmod +x %s", path, path)
		} else {
			// Gost 采用 3.0 稳定版轻量内核
			downloadCmd = fmt.Sprintf("curl -L https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_%s.tar.gz | tar -xz -C /tmp && mv /tmp/gost %s && chmod +x %s", arch, path, path)
		}

		cmd := exec.Command("sh", "-c", downloadCmd)
		if err := cmd.Run(); err != nil {
			log.Printf("[Forward] 自动安装 %s 失败，请确认系统环境是否有 curl: %v", bin, err)
		} else {
			log.Printf("[Forward] 成功安装 %s 到 %s", bin, path)
		}
	}
}

// CleanResiduals 启动时清空由本程序拉起的历史孤儿进程与残留 iptables 规则
func (fm *ForwardManager) CleanResiduals() {
	if runtime.GOOS == "windows" {
		return
	}

	log.Println("[Forward] 正在初始化清理残留的 realm 和 gost 端口转发实例...")
	// 1. 杀死残留的进程
	exec.Command("pkill", "-f", "realm -c /etc/stealthforward/realm/").Run()
	exec.Command("pkill", "-f", "gost -L tcp://").Run()

	// 2. 清理遗留的 iptables 规则
	cleanIptablesRules()
}

// ApplyRules 应用并同步最新的端口转发规则 (核心高可用更新)
func (fm *ForwardManager) ApplyRules(rules []models.PortForward) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// 1. 整理当前传入的有效规则 ID 集合
	activeRules := make(map[uint]models.PortForward)
	for _, r := range rules {
		if r.Status == "running" {
			activeRules[r.ID] = r
		}
	}

	// 2. 停止已被删除或状态改变为 paused 的实例
	for id, inst := range fm.instances {
		newRule, exists := activeRules[id]
		// 如果新配置里规则不存在了，或者规则配置有改变 (比如修改了目标地址或端口)
		if !exists || newRule.ListenPort != inst.Rule.ListenPort || newRule.TargetAddr != inst.Rule.TargetAddr || newRule.Type != inst.Rule.Type || newRule.TunnelType != inst.Rule.TunnelType {
			log.Printf("[Forward] 停止并释放转发规则 [%s] (ID: %d, Port: %d)", inst.Rule.Name, inst.Rule.ID, inst.Rule.ListenPort)
			fm.stopInstance(inst)
			delete(fm.instances, id)
			// 注意：不要删除 lastBytes 缓存，防止上报增量被漏计
		}
	}

	// 3. 启动最新且未在运行的规则
	for id, rule := range activeRules {
		if _, running := fm.instances[id]; !running {
			log.Printf("[Forward] 启动转发规则 [%s] (ID: %d, Engine: %s, Port: %d -> Target: %s)", rule.Name, rule.ID, rule.Type, rule.ListenPort, rule.TargetAddr)
			inst, err := fm.startInstance(rule)
			if err != nil {
				log.Printf("[Forward] 启动规则 [%s] 失败: %v", rule.Name, err)
				continue
			}
			fm.instances[id] = inst
		}
	}

	fm.lastConfig = rules
}

// startInstance 独立进程拉起
func (fm *ForwardManager) startInstance(rule models.PortForward) (*PortForwardInstance, error) {
	var cmd *exec.Cmd
	stopChan := make(chan struct{})

	if runtime.GOOS == "windows" {
		// Windows 仅作测试，不做真实转发拉起
		return &PortForwardInstance{Rule: rule, Cmd: nil, StopChan: stopChan}, nil
	}

	// 确保配置文件目录存在
	configDir := "/etc/stealthforward/realm"
	os.MkdirAll(configDir, 0755)

	if rule.Type == "realm" {
		// Realm 端口独立配置文件配置
		configPath := filepath.Join(configDir, fmt.Sprintf("pf_%d.json", rule.ID))
		cfgContent := fmt.Sprintf(`{
  "listening_addresses": ["0.0.0.0"],
  "endpoints": [
    {
      "listen": "0.0.0.0:%d",
      "remote": "%s"
    }
  ]
}`, rule.ListenPort, rule.TargetAddr)

		if err := os.WriteFile(configPath, []byte(cfgContent), 0644); err != nil {
			return nil, fmt.Errorf("failed to write realm config: %w", err)
		}
		cmd = exec.Command("/usr/local/bin/realm", "-c", configPath)

	} else {
		// Gost 直接命令行方式拉起 (默认支持 TCP + UDP 双向中转)
		if rule.TunnelType == "none" || rule.TunnelType == "" {
			cmd = exec.Command("/usr/local/bin/gost",
				"-L", fmt.Sprintf("tcp://:%d/%s", rule.ListenPort, rule.TargetAddr),
				"-L", fmt.Sprintf("udp://:%d/%s", rule.ListenPort, rule.TargetAddr),
			)
		} else {
			// 如果启用 gost 隧道 (此处作为预留)
			cmd = exec.Command("/usr/local/bin/gost",
				"-L", fmt.Sprintf("tcp://:%d/%s", rule.ListenPort, rule.TargetAddr),
			)
		}
	}

	// 启动进程，并重定向 Stdout 和 Stderr 写入 /dev/null 以防内存泄露
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// 挂载 iptables 流量统计计数器
	setupIptables(rule.ID, rule.ListenPort)

	// 开启协程守护该进程，防止内存泄露和僵尸进程
	go func() {
		err := cmd.Wait()
		select {
		case <-stopChan:
			// 被主动停止，正常退出
		default:
			// 异常退出，打印日志
			log.Printf("[Forward] 转发规则 ID: %d (Port: %d) 意外退出: %v", rule.ID, rule.ListenPort, err)
		}
	}()

	return &PortForwardInstance{
		Rule:     rule,
		Cmd:      cmd,
		StopChan: stopChan,
	}, nil
}

// stopInstance 安全释放进程与规则
func (fm *ForwardManager) stopInstance(inst *PortForwardInstance) {
	close(inst.StopChan)

	if inst.Cmd != nil && inst.Cmd.Process != nil {
		// 强杀子进程
		inst.Cmd.Process.Kill()
	}

	// 卸载该规则对应的 iptables 计数器
	removeIptables(inst.Rule.ID, inst.Rule.ListenPort)
}

// GetIncrementTraffic 计算并提取本轮上报的流量增量，并将基准更新 (防止爆内存，只存储活跃 ID)
func (fm *ForwardManager) GetIncrementTraffic() map[uint]models.TrafficStat {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	increments := make(map[uint]models.TrafficStat)

	for id, current := range fm.traffic {
		last, exists := fm.lastBytes[id]
		if !exists {
			// 说明是本轮第一次记录流量，增量就是当前值
			increments[id] = current
			fm.lastBytes[id] = current
		} else {
			// 计算差值
			upDiff := current.Upload - last.Upload
			downDiff := current.Download - last.Download

			// 处理计数器重置的情况 (比如系统重启或 iptables -F 导致计数归零)
			if upDiff < 0 {
				upDiff = current.Upload
			}
			if downDiff < 0 {
				downDiff = current.Download
			}

			if upDiff > 0 || downDiff > 0 {
				increments[id] = models.TrafficStat{
					Upload:   upDiff,
					Download: downDiff,
				}
				// 更新缓存基准
				fm.lastBytes[id] = current
			}
		}
	}

	return increments
}

// collectTrafficLoop 流量采集循环 (10秒一次，避免频繁 fork 浪费算力/内存)
func (fm *ForwardManager) collectTrafficLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		if runtime.GOOS == "windows" {
			continue
		}

		fm.readIptablesTraffic()
	}
}

// readIptablesTraffic 运行 iptables 读取并解析流量，极其温和
func (fm *ForwardManager) readIptablesTraffic() {
	// 1. 获取 INPUT (下载量)
	inputBytes, err := exec.Command("iptables", "-vx", "-L", "INPUT").Output()
	if err != nil {
		return
	}

	// 2. 获取 OUTPUT (上传量)
	outputBytes, err := exec.Command("iptables", "-vx", "-L", "OUTPUT").Output()
	if err != nil {
		return
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	// 逐行匹配解析
	scannerIn := bufio.NewScanner(bytes.NewReader(inputBytes))
	for scannerIn.Scan() {
		line := scannerIn.Text()
		if matches := pfInRegex.FindStringSubmatch(line); matches != nil {
			bytesVal, _ := strconv.ParseInt(matches[1], 10, 64)
			ruleID, _ := strconv.ParseUint(matches[3], 10, 32)
			
			stat := fm.traffic[uint(ruleID)]
			stat.Download = bytesVal // INPUT 对应的是用户的下载量
			fm.traffic[uint(ruleID)] = stat
		}
	}

	scannerOut := bufio.NewScanner(bytes.NewReader(outputBytes))
	for scannerOut.Scan() {
		line := scannerOut.Text()
		if matches := pfOutRegex.FindStringSubmatch(line); matches != nil {
			bytesVal, _ := strconv.ParseInt(matches[1], 10, 64)
			ruleID, _ := strconv.ParseUint(matches[3], 10, 32)

			stat := fm.traffic[uint(ruleID)]
			stat.Upload = bytesVal // OUTPUT 对应的是用户的上传量
			fm.traffic[uint(ruleID)] = stat
		}
	}
}

// ================= iptables 防火墙精细化交互操作 =================

func setupIptables(ruleID uint, port int) {
	// 挂载前先尝试清除，以防多次挂载规则膨胀
	removeIptables(ruleID, port)

	// INPUT (下载计费)
	exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%d", ruleID)).Run()
	exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%d", ruleID)).Run()

	// OUTPUT (上传计费)
	exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%d", ruleID)).Run()
	exec.Command("iptables", "-I", "OUTPUT", "-p", "udp", "--sport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%d", ruleID)).Run()
}

func removeIptables(ruleID uint, port int) {
	// 删除 TCP
	exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%d", ruleID)).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%d", ruleID)).Run()

	// 删除 UDP
	exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%d", ruleID)).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--sport", strconv.Itoa(port), "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%d", ruleID)).Run()
}

func cleanIptablesRules() {
	// 批量找出我们加的 comment 并删除
	inputBytes, err := exec.Command("iptables", "-vx", "-L", "INPUT").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(inputBytes))
		for scanner.Scan() {
			line := scanner.Text()
			if matches := pfInRegex.FindStringSubmatch(line); matches != nil {
				port := matches[2]
				ruleID := matches[3]
				exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%s", ruleID)).Run()
				exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", port, "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_in_%s", ruleID)).Run()
			}
		}
	}

	outputBytes, err := exec.Command("iptables", "-vx", "-L", "OUTPUT").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(outputBytes))
		for scanner.Scan() {
			line := scanner.Text()
			if matches := pfOutRegex.FindStringSubmatch(line); matches != nil {
				port := matches[2]
				ruleID := matches[3]
				exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", port, "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%s", ruleID)).Run()
				exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--sport", port, "-m", "comment", "--comment", fmt.Sprintf("stealth_pf_out_%s", ruleID)).Run()
			}
		}
	}
}
