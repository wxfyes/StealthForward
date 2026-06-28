# StealthForward v3.6.39

StealthForward 是一个高性能的流量转发和中转管理系统，专为复杂的网络环境设计。

> **注意**: 本项目目前处于活跃开发阶段。
它基于 "First-Principles" 架构设计，利用 `Sing-box` 内核的强大能力，将传统的端口转发升级为具备**流量清洗**、**精准审计**和**多路分流**能力的智能路由中心。

## ✨ 核心特性

### 1. 🛡️ 极致隐身 (Stealth Mode)
*   **协议隧道化**：拒绝裸奔。所有中转流量均封装在 `VLESS + XTLS-Vision` 或 `Reality` 协议中，完美伪装成正常的浏览器 HTTPS 流量，有效规避 GFW 主动探测。
*   **Web 伪装**：内置 Nginx 伪装服务，支持自动申请/更新 SSL 证书，提供真实的 fallback 网页。

### 2. 🔀 多端口物理分流 (Multi-Port Routing)
*   **单机多入口**：支持在同一台机器上监听多个端口（如 `4433`, `4434`），每个端口可独立映射到不同的落地国家（如 `马`、`印`）。
*   **物理隔离**：基于端口的物理级路由隔离，确保不同套餐/不同地区的用户流量互不干扰。

### 3. 💰 100% 精准流量审计 (Precision Accounting)
*   **内核级 Hook**：独家研发的 Agent 钩子技术，强制在用户态（User-Space）捕获流量。
*   **拒绝 Splice 偷跑**：彻底解决了 Linux 内核 TCP Splice/Zero-Copy 技术导致的“只记握手包、漏记视频流”的业界顽疾。
*   **多协议支持**：完美支持 TCP、UDP (QUIC/HTTP3) 全协议计费。

### 4. 🖥️ 现代化可视化在板 (Modern UI)
*   **极简仪表盘**：全新设计的 "Glass" 风格 UI，实时监控节点状态和流量。
*   **动态管理**：支持在线添加、编辑、删除分流规则，修改端口立即生效（支持 PUT 热更新）。
*   **V2Board 对接**：无缝对接 V2Board 及兼容面板，自动化同步用户和节点信息。

---

## 🚀 快速部署

我们提供了一键安装脚本，支持在 `Ubuntu 20.04+`, `Debian 10+`, `CentOS 7+` 上快速部署。

### 1. 更新安装脚本
```bash
wget -O /root/install.sh https://raw.githubusercontent.com/wangn9900/StealthForward/main/scripts/install.sh && chmod +x /root/install.sh
```

### 2. 安装/更新
运行脚本并按照提示操作：
```bash
./install.sh
```

*   **选项 1**: 安装 **Controller** (中控端/面板端)
*   **选项 2**: 安装 **Agent** (中转机/入口端) - *自动配置内置核心，无需额外操作*

---

## 📖 使用指南

### 场景一：单入口多落地 (Multi-Target)
假设您有一台中转机 `Transit-CN`，希望同时提供 `新加坡` 和 `日本` 两条线路：

1.  **添加落地机 (Exits)**：
    *   在面板添加 `Exit-SG` (新加坡) 和 `Exit-JP` (日本) 的对接信息。
2.  **配置分流规则 (Mappings)**：
    *   新建规则：`Entry: Transit-CN` -> `V2B Node: 101` -> `Target: Exit-SG` -> `Port: 4431`
    *   新建规则：`Entry: Transit-CN` -> `V2B Node: 102` -> `Target: Exit-JP` -> `Port: 4432`
3.  **生效**：
    *   用户连接 `4431` 端口，流量自动转发至新加坡，计费归属节点 101。
    *   用户连接 `4432` 端口，流量自动转发至日本，计费归属节点 102。

### 场景二：V2Board 对接
在 **入口节点 (Entry)** 编辑页中填写：
*   **API 地址**: 您的 V2Board 网址
*   **通讯密钥**: Admin Config 中的 Key
*   **节点 ID**: 默认绑定的节点 ID

---

## 🛠️ 技术架构

`User` <==> `[Stealth-Agent:443]` <==> `[Sing-box Core]` <==> `[Exit Node]`
                    ⬇️
            `[Stealth-Controller]` (API/DB/UI)

*   **Agent**: 负责流量劫持、鉴权、统计汇报。
*   **Controller**: 负责策略下发、证书管理、V2Board 同步。

---

## ⚠️ 开发者与 AI 开发提示 (Developer & AI Instructions)

### 关于魔改内核 (sing-box_mod) 与主控依赖同步的说明

*   **独立内核构建**：独立内核二进制 `sing-box-mod`（中转机上的 `/usr/local/bin/stealth-core`）在 GitHub CI 流程中，会直接通过克隆并编译 `wxfyes/sing-box_mod` 仓库的最新代码生成。
*   **Agent 内置内核构建**：Agent 命令行带 `-internal` 参数时会启用内置内核服务。在编译 `stealth-agent` 二进制文件时，GitHub CI 使用了 **`-mod=vendor`** 参数。
*   **同步要求**：
    由于使用 `vendor` 依赖树编译，**所有对 `sing-box_mod` 仓库的源码修改，都必须物理同步至 `StealthForward` 的 `vendor/github.com/sagernet/sing-box/` 目录下**！
    *   **同步方法**：在 `StealthForward` 项目根目录下执行 `go mod vendor`，或直接物理复制替换 `vendor/github.com/sagernet/sing-box/` 中的对应修改文件，并提交 `vendor/` 的变更推送。
    *   **若不同步**：直接编译推送主控，内置内核（Agent -internal）将使用旧版缓存，导致最新修改的内核功能无法生效。

---
*Powered by StealthForward Team | v2.1.46 Stable*
