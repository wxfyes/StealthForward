package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// SNIRouter 在 443 端口上运行轻量级 SNI 嗅探预分流
type SNIRouter struct {
	mu       sync.RWMutex
	routes   map[string]int // SNI (小写) -> 本地目标端口 (例如 10001)
	fallback string         // 未匹配或非 TLS 流量回落地址，例如 "127.0.0.1:8081"
	port     int            // 对外监听端口 (如 443, 8443, 2053, 2096)
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
}

func NewSNIRouter() *SNIRouter {
	return &SNIRouter{
		routes:   make(map[string]int),
		fallback: "127.0.0.1:8081",
		port:     443,
	}
}

// UpdateRoutes 更新 SNI 路由表并根据需要启动或停止对外端口监听
func (r *SNIRouter) UpdateRoutes(newRoutes map[string]int, fallback string, publicPort int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if publicPort <= 0 {
		publicPort = 443
	}

	portChanged := r.running && r.port != publicPort
	r.port = publicPort

	// 清理格式并转换为小写
	cleaned := make(map[string]int)
	for sni, port := range newRoutes {
		s := strings.ToLower(strings.TrimSpace(sni))
		if strings.Contains(s, ":") {
			s = strings.Split(s, ":")[0]
		}
		if s != "" && port > 0 {
			cleaned[s] = port
		}
	}
	r.routes = cleaned
	if fallback != "" {
		r.fallback = fallback
	}

	log.Printf("[SNI-Router] 更新路由表，对外统一分流端口: %d, 当前规则数: %d, Fallback: %s", r.port, len(r.routes), r.fallback)
	for sni, port := range r.routes {
		log.Printf("[SNI-Router]   -> SNI: %s => 127.0.0.1:%d", sni, port)
	}

	// 如果端口改变了，先停掉旧端口
	if portChanged {
		r.stopLocked()
	}

	// 如果有规则且未启动，则启动对外端口监听
	if len(r.routes) > 0 && !r.running {
		r.startLocked()
	} else if len(r.routes) == 0 && r.running {
		// 如果规则被清空，则释放监听
		r.stopLocked()
	}
}

func (r *SNIRouter) startLocked() {
	addr := fmt.Sprintf("0.0.0.0:%d", r.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[SNI-Router] 警告: 监听 %s 失败 (可能端口已被占用): %v", addr, err)
		return
	}

	r.listener = ln
	r.running = true
	r.ctx, r.cancel = context.WithCancel(context.Background())
	log.Printf("[SNI-Router] 成功监听 %s，智能分流已就绪", addr)

	go r.acceptLoop(ln, r.ctx)
}

func (r *SNIRouter) stopLocked() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.listener != nil {
		r.listener.Close()
		r.listener = nil
	}
	r.running = false
	log.Printf("[SNI-Router] 已停止对外分流端口监听 (%d)", r.port)
}

func (r *SNIRouter) acceptLoop(ln net.Listener, ctx context.Context) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[SNI-Router] Accept 错误: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go r.handleConn(conn)
	}
}

func (r *SNIRouter) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 设置首包超时，防挂死
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	sni, ok := extractSNI(buf[:n])

	r.mu.RLock()
	targetPort := 0
	if ok {
		targetPort = r.routes[strings.ToLower(sni)]
	}
	fallback := r.fallback
	r.mu.RUnlock()

	var targetAddr string
	if targetPort > 0 {
		targetAddr = fmt.Sprintf("127.0.0.1:%d", targetPort)
		// log.Printf("[SNI-Router] 匹配成功: SNI=%s -> %s", sni, targetAddr)
	} else {
		targetAddr = fallback
		// log.Printf("[SNI-Router] 未匹配或探针: SNI=%s -> Fallback=%s", sni, targetAddr)
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
	if err != nil {
		log.Printf("[SNI-Router] 连接后端 %s 失败: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// 把预读出的首包完整送入后端
	if _, err := targetConn.Write(buf[:n]); err != nil {
		return
	}

	// 双向全双工转发 (XTLS-Vision 等流控协议在此透明透传)
	pipe(clientConn, targetConn)
}

func pipe(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
		if tc, ok := c1.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// extractSNI 从 TLS ClientHello 包解析 ServerName (SNI)
func extractSNI(data []byte) (string, bool) {
	if len(data) < 42 {
		return "", false
	}
	// TLS Handshake Record
	if data[0] != 0x16 {
		return "", false
	}
	// ClientHello
	if data[5] != 0x01 {
		return "", false
	}

	pos := 43
	if len(data) <= pos {
		return "", false
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if len(data) <= pos+2 {
		return "", false
	}

	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherLen
	if len(data) <= pos+1 {
		return "", false
	}

	compLen := int(data[pos])
	pos += 1 + compLen
	if len(data) <= pos+2 {
		return "", false
	}

	extTotalLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	if len(data) < pos+extTotalLen {
		extTotalLen = len(data) - pos
	}
	end := pos + extTotalLen

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 0 { // server_name 扩展
			if extLen >= 5 {
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				if pos+5+nameLen <= end {
					return string(data[pos+5 : pos+5+nameLen]), true
				}
			}
		}
		pos += extLen
	}

	return "", false
}
