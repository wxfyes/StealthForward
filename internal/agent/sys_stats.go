package agent

import (
	"bufio"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/wangn9900/StealthForward/internal/models"
)

var (
	lastNetIn  int64
	lastNetOut int64
	lastCheck  time.Time
)

func countConnectionsLinux(proto string) uint64 {
	var count uint64
	paths := []string{
		"/proc/net/" + proto,
		"/proc/net/" + proto + "6",
	}

	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		// Skip header line
		if scanner.Scan() {
			for scanner.Scan() {
				count++
			}
		}
		file.Close()
	}

	return count
}

func GetSystemStats() *models.SystemStats {
	stats := &models.SystemStats{}

	// CPU
	percent, _ := cpu.Percent(time.Second, false)
	if len(percent) > 0 {
		stats.CPU = percent[0]
	}

	// Memory
	vm, _ := mem.VirtualMemory()
	if vm != nil {
		stats.Mem = vm.UsedPercent
	}

	// Swap
	sw, _ := mem.SwapMemory()
	if sw != nil {
		stats.Swap = sw.UsedPercent
	}

	// Disk
	d, _ := disk.Usage("/")
	if d != nil {
		stats.Disk = d.UsedPercent
	}

	// Load
	l, _ := load.Avg()
	if l != nil {
		stats.Load1 = l.Load1
		stats.Load5 = l.Load5
		stats.Load15 = l.Load15
	}

	// Uptime
	u, _ := host.Uptime()
	stats.Uptime = int64(u)

	// Hostname
	info, _ := host.Info()
	if info != nil {
		stats.Hostname = info.Hostname
	}

	// Network Speed
	io, _ := net.IOCounters(false)
	if len(io) > 0 {
		now := time.Now()
		currIn := int64(io[0].BytesRecv)
		currOut := int64(io[0].BytesSent)

		if !lastCheck.IsZero() {
			duration := now.Sub(lastCheck).Seconds()
			if duration > 0 {
				stats.NetIn = int64(float64(currIn-lastNetIn) / duration)
				stats.NetOut = int64(float64(currOut-lastNetOut) / duration)
			}
		}
		stats.NetTrafficIn = currIn
		stats.NetTrafficOut = currOut
		lastNetIn = currIn
		lastNetOut = currOut
		lastCheck = now
	}

	// Connections (TCP & UDP)
	stats.TCPConn = countConnectionsLinux("tcp")
	stats.UDPConn = countConnectionsLinux("udp")

	return stats
}
