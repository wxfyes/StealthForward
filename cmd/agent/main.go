package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/wangn9900/StealthForward/internal/agent"
)

func main() {
	setRLimit()
	// 1. 定义命令行参数
	controllerAddr := flag.String("controller", "http://your-controller-ip:8080", "Controller API address")
	nodeID := flag.Int("node", 1, "Entry Node ID")
	syncInterval := flag.Int("interval", 60, "Sync interval in seconds")
	localDir := flag.String("dir", "/etc/stealthforward/core", "Directory for sing-box config")
	masqueradeDir := flag.String("www", "/etc/stealthforward/www", "Directory for masquerade site")
	corePath := flag.String("corepath", "/usr/local/bin/stealth-core", "Path to isolated sing-box binary")
	fallbackPort := flag.Int("fallback-port", 8081, "Port for the local masquerade server")
	adminToken := flag.String("token", "", "Admin token for controller authentication")
	useInternal := flag.Bool("internal", false, "Use internal sing-box core for accurate traffic stats")
	once := flag.Bool("once", false, "Run once and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("StealthForward Agent Version: %s\n", agent.Version)
		return
	}

	// 智能探测内核路径
	if _, err := os.Stat(*corePath); os.IsNotExist(err) {
		candidates := []string{"/usr/local/bin/stealth-core", "/usr/bin/stealth-core", "/usr/local/bin/sing-box"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*corePath = c
				break
			}
		}
		if lp, err := exec.LookPath("stealth-core"); err == nil {
			*corePath = lp
		}
	}

	log.Printf("StealthForward Agent starting for Node ID: %d", *nodeID)
	log.Printf("Core path: %s", *corePath)

	// 2. 初始化 Agent
	ag := agent.NewAgent(agent.Config{
		ControllerAddr: *controllerAddr,
		NodeID:         *nodeID,
		LocalConfigDir: *localDir,
		MasqueradeDir:  *masqueradeDir,
		SingBoxPath:    *corePath,
		UseInternal:    *useInternal,
		AdminToken:     *adminToken,
	})

	// 3. 启动本地伪装服务器（用于 SNI 回落目的地）
	ag.StartMasqueradeServer(*fallbackPort)

	// 如果指定了 -once，运行一次后退出
	if *once {
		ag.RunOnce()
		return
	}

	// 4. 循环同步任务
	ticker := time.NewTicker(time.Duration(*syncInterval) * time.Second)
	defer ticker.Stop()

	// 启动时立即运行一次
	ag.RunOnce()

	for range ticker.C {
		ag.RunOnce()
	}
}
