package agent

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TrafficStorage 存储单个用户的流量
type TrafficStorage struct {
	UpCounter   atomic.Int64
	DownCounter atomic.Int64
}

// HookServer 实现 sing-box 的 ConnectionTracker 接口
type HookServer struct {
	counter sync.Map // map[string]*TrafficStorage
}

func (h *HookServer) ModeList() []string {
	return nil
}

func (h *HookServer) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) net.Conn {
	log.Printf("[Stats-TCP] User: %s, Inbound: %s, Outbound: %s (%s)", m.User, m.Inbound, outbound.Tag(), outbound.Type())
	if m.User == "" {
		return conn
	}

	val, _ := h.counter.LoadOrStore(m.User, &TrafficStorage{})
	storage := val.(*TrafficStorage)

	// 使用标准 Conn 包装，不透传 SyscallConn，强制禁用 Splice 以捕获在用户态的流量
	return &ConnCounter{
		conn:    conn,
		storage: storage,
	}
}

func (h *HookServer) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	log.Printf("[Stats-UDP] User: %s, Inbound: %s, Outbound: %s (%s)", m.User, m.Inbound, outbound.Tag(), outbound.Type())
	if m.User == "" {
		return conn
	}

	val, _ := h.counter.LoadOrStore(m.User, &TrafficStorage{})
	storage := val.(*TrafficStorage)

	return &PacketConnCounter{
		PacketConn: conn,
		storage:    storage,
	}
}

// ConnCounter 包装 net.Conn 以统计流量 (TCP)
// 显式实现 net.Conn 且不使用嵌入，以隐藏 ReaderFrom/WriterTo/SyscallConn 接口
// 并防止任何 Unwrap/反射机制获取到内部的物理 TCP 连接
type ConnCounter struct {
	conn    net.Conn
	storage *TrafficStorage
}

func (c *ConnCounter) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	if n > 0 {
		c.storage.UpCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	if n > 0 {
		c.storage.DownCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) Close() error {
	return c.conn.Close()
}

func (c *ConnCounter) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ConnCounter) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *ConnCounter) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *ConnCounter) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *ConnCounter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *ConnCounter) ReadFrom(r io.Reader) (n int64, err error) {
	// 强制降级到 copy loop
	return io.Copy(struct{ io.Writer }{c}, r)
}

// PacketConnCounter 包装 N.PacketConn 以统计流量 (UDP/QUIC)
type PacketConnCounter struct {
	N.PacketConn
	storage *TrafficStorage
}

// ReadPacket captures UDP Upload traffic
func (c *PacketConnCounter) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil {
		c.storage.UpCounter.Add(int64(buffer.Len()))
	}
	return
}

// WritePacket captures UDP Download traffic
func (c *PacketConnCounter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	l := int64(buffer.Len())

	// Defensive Copy: Ensure sufficient headroom for VMess/Trojan Mux header extension.
	// We require at least 32 bytes of headroom to be safe.
	const neededHeadroom = 32
	if buffer.Start() < neededHeadroom {
		newBuf := buf.NewPacket()
		// Resize sets start=neededHeadroom and end=start+buffer.Len()
		newBuf.Resize(neededHeadroom, buffer.Len())
		copy(newBuf.Bytes(), buffer.Bytes())

		buffer.Release()
		buffer = newBuf
	}

	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		c.storage.DownCounter.Add(l)
		// log.Printf("UDP WritePacket (Down) %d", l)
	}
	return err
}

// GetStats 获取并重置流量统计
func (h *HookServer) GetStats() map[string][2]int64 {
	stats := make(map[string][2]int64)
	h.counter.Range(func(key, value interface{}) bool {
		user := key.(string)
		storage := value.(*TrafficStorage)
		up := storage.UpCounter.Swap(0)
		down := storage.DownCounter.Swap(0)
		if up > 0 || down > 0 {
			stats[user] = [2]int64{up, down}
		}
		return true
	})
	return stats
}
