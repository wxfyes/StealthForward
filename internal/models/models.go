package models

import "time"

// EntryNode 代表入口服务器（海外机）
type EntryNode struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Port          int    `json:"port"`           // 通常为 443 或 8443
	Domain        string `json:"domain"`         // 用于 TLS
	Certificate   string `json:"certificate"`    // 证书文件路径
	Key           string `json:"key"`            // 私钥文件路径
	CertBody      string `json:"cert_body"`      // 证书内容备份 (用于换机无感恢复)
	KeyBody       string `json:"key_body"`       // 私钥内容备份
	Fallback      string `json:"fallback"`       // 回落地址，例如 "127.0.0.1:8080"
	CertTask      bool   `json:"cert_task"`      // 是否有待处理的证书申请任务
	TargetExitID  uint   `json:"target_exit_id"` // 默认的一键转落地节点 ID（作为备用）
	UnlockExitID  uint   `json:"unlock_exit_id"`  // 解锁落地节点 ID (可选)
	UnlockDomains string `json:"unlock_domains"`  // 自定义解锁域名，逗号或换行分隔 (可选)
	Protocol      string `json:"protocol"`       // anytls, vless, vmess, trojan
	Transport     string `json:"transport"`      // tcp, grpc, ws, h2 (传输层类型)
	GrpcService   string `json:"grpc_service"`   // gRPC service name (如 "grpc")
	Security      string `json:"security"`       // xtls-vision
	PaddingScheme string `json:"padding_scheme"` // AnyTLS 填充方案

	// V2Board 同步配置（全局默认）
	V2boardURL    string `json:"v2board_url"`     // V2Board API 地址
	V2boardKey    string `json:"v2board_key"`     // 通讯密钥
	V2boardNodeID int    `json:"v2board_node_id"` // 默认节点 ID
	V2boardType   string `json:"v2board_type"`    // v2ray, shadowsocks, trojan

	// 云平台绑定 (用于一键换 IP)
	CloudProvider   string `json:"cloud_provider"`    // "aws_ec2", "aws_lightsail", "none"
	CloudRegion     string `json:"cloud_region"`      // "ap-northeast-1"
	CloudInstanceID string `json:"cloud_instance_id"` // EC2: "i-0123..." / Lightsail: "stealth-xxx"
	CloudRecordName string `json:"cloud_record_name"` // Cloudflare 子域名 (如 "transitnode")
	AutoRotateIP    bool   `json:"auto_rotate_ip"`    // 是否启用自动换 IP

	// Reality 配置
	RealityEnabled     bool   `json:"reality_enabled"`     // 是否启用 Reality
	RealityServerName  string `json:"reality_server_name"` // SNI / ServerName (e.g. www.samsung.com)
	RealityFallback    string `json:"reality_fallback"`    // Dest / ServerAddress (e.g. www.samsung.com:443)
	RealityPrivateKey  string `json:"reality_private_key"` // Private Key
	RealityShortID     string `json:"reality_short_id"`    // ShortId
	RealityFingerprint string `json:"reality_fingerprint"` // FingerPrint (chrome, safari, etc.)

	// 流量统计 (持久化)
	TotalUpload   int64 `json:"total_upload"`   // 累计上行流量 (bytes)
	TotalDownload int64 `json:"total_download"` // 累计下行流量 (bytes)

	CreatedAt time.Time `json:"created_at"`
}

// NodeMapping 定义了同一入口下不同 V2Board 节点到不同落地机的映射关系
type NodeMapping struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	EntryNodeID   uint      `json:"entry_node_id"`   // 关联入口节点
	V2boardNodeID int       `json:"v2board_node_id"` // V2Board 那边的节点 ID
	TargetExitID  uint      `json:"target_exit_id"`  // 对应的落地节点 ID
	UnlockExitID  uint      `json:"unlock_exit_id"`  // 解锁落地节点 ID (可选)
	UnlockDomains string    `json:"unlock_domains"`  // 自定义解锁域名，逗号或换行分隔 (可选)
	V2boardType   string    `json:"v2board_type"`    // 节点类型
	Port          int       `json:"port"`            // 该映射独立监听的端口（为 0 时使用入口默认端口）
	CreatedAt     time.Time `json:"created_at"`
}

// ExitNode 代表落地服务器（小鸡）
type ExitNode struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // shadowsocks, vmess, vless
	Config   string `json:"config"`   // 存储具体的协议配置 (JSON string)

	// 流量统计 (持久化)
	TotalUpload   int64 `json:"total_upload"`   // 累计上行流量 (bytes)
	TotalDownload int64 `json:"total_download"` // 累计下行流量 (bytes)

	CreatedAt time.Time `json:"created_at"`
}

// ForwardingRule 定义了最终的转发映射关系 (用户级)
type ForwardingRule struct {
	ID          uint   `json:"id"`
	UserID      string `json:"user_id"`     // 对应 VLESS 的 UUID
	V2boardUID  uint   `json:"v2board_uid"` // 对应 V2Board 的用户 ID，用于上报流量
	UserEmail   string `json:"user_email"`  // 对应 VLESS 的 Email，用于识别流量
	EntryNodeID uint   `json:"entry_node_id"`
	ExitNodeID  uint   `json:"exit_node_id"`
	Enabled     bool   `json:"enabled"`
}

// UserTraffic 代表单个用户的流量统计
type UserTraffic struct {
	UserEmail string `json:"user_email"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
}

// SystemStats 代表服务器状态探针数据
type SystemStats struct {
	CPU      float64 `json:"cpu"`       // CPU 使用率 (%)
	Mem      float64 `json:"mem"`       // 内存使用率 (%)
	Swap     float64 `json:"swap"`      // Swap 使用率 (%)
	Disk     float64 `json:"disk"`      // 硬盘使用率 (%)
	NetIn    int64   `json:"net_in"`    // 近期下行速率 (bytes/s)
	NetOut   int64   `json:"net_out"`   // 近期上行速率 (bytes/s)
	Load1    float64 `json:"load1"`     // 负载 1min
	Load5    float64 `json:"load5"`     // 负载 5min
	Load15   float64 `json:"load15"`    // 负载 15min
	Uptime   int64   `json:"uptime"`    // 在线时间 (秒)
	ReportAt int64   `json:"report_at"` // 上报时间戳
}

// NodeTrafficReport 节点上报的流量汇总
type NodeTrafficReport struct {
	NodeID        uint          `json:"node_id"`
	Traffic       []UserTraffic `json:"traffic"`
	TotalUpload   int64         `json:"total_upload"`
	TotalDownload int64         `json:"total_download"`
	Stats         *SystemStats  `json:"stats,omitempty"` // 探针数据
}

type TrafficStat struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}
