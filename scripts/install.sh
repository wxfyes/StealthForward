#!/bin/bash

# StealthForward 一键安装脚本
# Support OS: Ubuntu, Debian, CentOS 7+, Alpine

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 私有仓库 Auth 支持 ---
GH_AUTH_HEADER=""
if [ -n "$GH_TOKEN" ]; then
    GH_AUTH_HEADER="Authorization: token $GH_TOKEN"
    echo -e "${GREEN}检测到 GH_TOKEN，已启用私有仓库认证模式${NC}"
fi

# 通用 GitHub API/Raw 请求封装
gh_curl() {
    if [ -n "$GH_AUTH_HEADER" ]; then
        curl -H "$GH_AUTH_HEADER" "$@"
    else
        curl "$@"
    fi
}

# 检查权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}错误: 请使用 root 权限运行此脚本。${NC}"
  exit 1
fi

# 自动检测系统及初始化系统
OS_RELEASE=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_RELEASE=$ID
elif [ -f /etc/redhat-release ]; then
    OS_RELEASE="centos"
elif grep -Eqi "alpine" /etc/issue; then
    OS_RELEASE="alpine"
fi

INIT_SYSTEM="systemd"
if [ "$OS_RELEASE" = "alpine" ] || [ -f /sbin/openrc-run ]; then
    INIT_SYSTEM="openrc"
fi

# 服务管理函数封装
service_command() {
    local action=$1
    local service=$2
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl "$action" "$service"
    else
        case "$action" in
            start)   rc-service "$service" start ;;
            stop)    rc-service "$service" stop ;;
            restart) rc-service "$service" restart ;;
            enable)  rc-update add "$service" default ;;
            disable) rc-update del "$service" default ;;
            status)  rc-service "$service" status ;;
            reload)  rc-service "$service" reload ;;
            daemon-reload) ;; # OpenRC 不需要
        esac
    fi
}

show_logo() {
  clear
  echo -e "${CYAN}"
  echo "  ____  _             _ _   _     _____                            _ "
  echo " / ___|| |_ ___  __ _| | |_| |__ |  ___|__  _ __ __      ____ _ _ __ __| |"
  echo " \___ \| __/ _ \/ _\` | | __| '_ \| |_ / _ \| '__\ \ /\ / / _\` | '__/ _\` |"
  echo "  ___) | ||  __/ (_| | | |_| | | |  _| (_) | |   \ V  V / (_| | | | (_| |"
  echo " |____/ \__\___|\__,_|_|\__|_| |_|_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|"
  echo -e "${NC}"
  echo -e "${PURPLE}--- 隐形转发面板 (StealthForward) | 海外入口专属优化 ---${NC}"
  echo ""
}

issue_certificate() {
  local domain=$1
  if [ -z "$domain" ]; then
    echo -e "${YELLOW}证书申请阶段: 若要使用 SSL 必须填入该节点对应的域名。${NC}"
    read -p "请输入当前节点的证书域名 (e.g. transit.example.com): " domain
  fi
  
  if [ -z "$domain" ]; then
    echo -e "${RED}警告: 域名为空，将跳过证书申请，sing-box 可能会因为找不到证书文件启动失败。${NC}"
    return 1
  fi

  # 检查证书是否已存在（避免重复申请被限速）
  local cert_dir="/etc/stealthforward/certs/$domain"
  if [ -f "$cert_dir/cert.crt" ] && [ -s "$cert_dir/cert.crt" ]; then
    echo -e "${GREEN}证书已存在于 $cert_dir，跳过申请（续期由 acme.sh cron 自动处理）。${NC}"
    return 0
  fi

  echo -e "${CYAN}正在通过 acme.sh 申请证书 for $domain ...${NC}"
  
  # 1. 安装依赖 (增加 cron，这是 acme.sh installer 报错 Pre-check failed 的常见原因)
  echo -e "${YELLOW}检查并安装 acme.sh 依赖 (socat, curl, cron)...${NC}"
  if [ "$OS_RELEASE" = "alpine" ]; then
    apk add socat curl dcron
    service_command enable dcron
    service_command start dcron
  elif command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y socat curl cron
    service_command enable cron
    service_command start cron
  elif command -v yum &> /dev/null; then
    yum install -y socat curl cronie
    service_command enable crond
    service_command start crond
  fi

  # 2. 安装 acme.sh
  if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    echo -e "${YELLOW}正在安装 acme.sh...${NC}"
    curl https://get.acme.sh | sh
    
    # 强制兜底：如果安装脚本失败，直接手动下载脚本文件
    if [ ! -f "/root/.acme.sh/acme.sh" ]; then
      echo -e "${YELLOW}标准安装失败，执行手动补救模式...${NC}"
      mkdir -p /root/.acme.sh
      curl -L https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o /root/.acme.sh/acme.sh
      chmod +x /root/.acme.sh/acme.sh
    fi
  fi
  
  local ACME="/root/.acme.sh/acme.sh"
  
  # 3. 注册账户 (LetsEncrypt)
  echo -e "${CYAN}正在注册 ACME 账户...${NC}"
  $ACME --register-account -m admin@$domain --server letsencrypt >> /var/log/stealth-init.log 2>&1
  
  # 4. 申请证书 (使用 Nginx Webroot 验证，因为伪装页已部署)
  echo -e "${CYAN}正在执行验证并申请证书 (Let's Encrypt)...${NC}"
  $ACME --issue --server letsencrypt -d $domain -w /var/www/html --force >> /var/log/stealth-init.log 2>&1
  
  if [ $? -eq 0 ]; then
    mkdir -p /etc/stealthforward/certs/$domain
    $ACME --install-cert -d $domain \
      --fullchain-file /etc/stealthforward/certs/$domain/cert.crt \
      --key-file /etc/stealthforward/certs/$domain/cert.key >> /var/log/stealth-init.log 2>&1
    echo -e "${GREEN}证书成功颁发并安装到 /etc/stealthforward/certs/$domain/ ${NC}"
    return 0
  else
    echo -e "${RED}Webroot 模式证书申请失败，正在分析原因...${NC}"
    echo -e "${YELLOW}尝试暴力 Standalone 模式 (需要暂时停止 Nginx)...${NC}"
    service_command stop nginx
    $ACME --issue --server letsencrypt -d $domain --standalone --force >> /var/log/stealth-init.log 2>&1
    local res=$?
    service_command start nginx
    if [ $res -eq 0 ]; then
       mkdir -p /etc/stealthforward/certs/$domain
       $ACME --install-cert -d $domain --fullchain-file /etc/stealthforward/certs/$domain/cert.crt --key-file /etc/stealthforward/certs/$domain/cert.key >> /var/log/stealth-init.log 2>&1
       echo -e "${GREEN}Standalone 模式证书申请成功！${NC}"
       return 0
    else
       echo -e "${RED}终极失败：即使 Standalone 模式也无法领证。请检查域名解析是否生效，或 80 端口是否被服务商防火墙拦截。${NC}"
    fi
    return 1
  fi
}

# 核心变量
REPO="wxfyes/StealthForward"
INSTALL_DIR="/etc/stealthforward"
BIN_DIR="/usr/local/bin"

# 自动检测架构
ARCH=$(uname -m)
case $ARCH in
  x86_64)  PLATFORM="amd64" ;;
  aarch64) PLATFORM="arm64" ;;
  *)       echo -e "${RED}不支持的架构: $ARCH${NC}"; exit 1 ;;
esac

download_binary() {
  local name=$1
  local target_name=$2
  local force_tag=$3

  if [ -n "$force_tag" ]; then
    echo -e "${YELLOW}使用指定版本: $force_tag${NC}"
    LATEST_TAG="$force_tag"
  else
    echo -e "${YELLOW}正在探测最新版本...${NC}"
    LATEST_TAG=$(gh_curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  fi
  
  if [ -z "$LATEST_TAG" ]; then
    echo -e "${RED}无法获取版本号，请检查网络或 GITHUB_TOKEN 配置。${NC}"
    exit 1
  fi

  echo -e "${YELLOW}正在下载 $name ($LATEST_TAG | $PLATFORM)...${NC}"
  
  # 对于私有仓库，Release 下载需要特殊处理 (通过 API 或者 带 Authorization 的重定向)
  # 这里尝试带 Token 的 API 下载方式
  if [ -n "$GH_TOKEN" ]; then
    # 获取 Asset ID
    ASSET_ID=$(gh_curl -s "https://api.github.com/repos/$REPO/releases/tags/$LATEST_TAG" | grep -B 1 "\"name\": \"${name}-${PLATFORM}\"" | grep '"id":' | head -n 1 | sed -E 's/.*: ([0-9]+),.*/\1/')
    if [ -n "$ASSET_ID" ]; then
        echo -e "${CYAN}通过 API 下载 Asset (ID: $ASSET_ID)...${NC}"
        gh_curl -L -f -H "Accept: application/octet-stream" \
             -o "$BIN_DIR/$target_name" \
             "https://api.github.com/repos/$REPO/releases/assets/$ASSET_ID"
    else
        # 降级：尝试普通 URL
        URL="https://github.com/$REPO/releases/download/$LATEST_TAG/${name}-${PLATFORM}"
        gh_curl -L -f -o "$BIN_DIR/$target_name" "$URL"
    fi
  else
    URL="https://github.com/$REPO/releases/download/$LATEST_TAG/${name}-${PLATFORM}"
    curl -L -f -o "$BIN_DIR/$target_name" "$URL"
  fi
  
  if [ $? -eq 0 ]; then
    chmod +x "$BIN_DIR/$target_name"
    echo -e "${GREEN}$name 安装成功!${NC}"
  else
    echo -e "${RED}$name 下载失败!${NC}"
    exit 1
  fi
}

install_sing_box() {
  echo -e "${YELLOW}正在安装隔离版 Stealth Core (魔改内核)...${NC}"
  
  # 先停止服务，避免文件被占用
  service_command stop stealth-core 2>/dev/null
  
  # 从 StealthForward Release 下载魔改版内核
  CORE_NAME="sing-box-mod"
  CORE_PATH="/usr/local/bin/stealth-core"
  CONF_DIR="/etc/stealthforward/core"
  
  mkdir -p $CONF_DIR
  
  echo -e "${CYAN}正在下载内核到 $CORE_PATH...${NC}"
  # 自动检测架构下载二进制
  if [ -n "$GH_TOKEN" ]; then
     # 复用上面的 API 下载逻辑或探测 Asset
     download_binary "sing-box-mod" "stealth-core"
  else
     curl -Lo "$CORE_PATH" "https://github.com/$REPO/releases/latest/download/sing-box-mod-$PLATFORM"
  fi
  
  chmod +x "$CORE_PATH"
  echo -e "${GREEN}隔离版内核安装成功!${NC}"

  echo -e "${GREEN}隔离版内核 (stealth-core) 已下载并安装到 $CORE_PATH (仅作为备用工具)${NC}"
  echo -e "${YELLOW}提示: Agent 将默认使用内置核心 (Internal Mode) 运行，无需启动 stealth-core 服务。${NC}"
}

install_controller() {
  show_logo
  echo -e "${BLUE}开始安装 StealthForward Controller (中控端)...${NC}"
  
  service_command stop stealth-controller 2>/dev/null
  
  mkdir -p $INSTALL_DIR/web
  download_binary "stealth-controller" "stealth-controller"

  # --- 新增：配置授权服务器地址 ---
  # --- 配置授权服务器地址 (默认留空，由Web端配置或智能Key覆盖) ---
  LICENSE_ENV_LINE=""


  echo -e "${YELLOW}正在同步可视化面板资源...${NC}"
  
  # 优先尝试从 Release 下载 web.zip (由 CI 自动构建)
  ZIP_NAME="web.zip"
  DOWNLOAD_SUCCESS=0

  if [ -n "$LATEST_TAG" ]; then
      if [ -n "$GH_TOKEN" ]; then
          ASSET_ID=$(gh_curl -s "https://api.github.com/repos/$REPO/releases/tags/$LATEST_TAG" | grep -B 1 "\"name\": \"$ZIP_NAME\"" | grep '"id":' | head -n 1 | sed -E 's/.*: ([0-9]+),.*/\1/')
          if [ -n "$ASSET_ID" ]; then
             gh_curl -L -f -H "Accept: application/octet-stream" -o "$INSTALL_DIR/web.zip" "https://api.github.com/repos/$REPO/releases/assets/$ASSET_ID" && DOWNLOAD_SUCCESS=1
          fi
      fi
      
      if [ $DOWNLOAD_SUCCESS -eq 0 ]; then
          ZIP_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/web.zip"
          gh_curl -L --fail --connect-timeout 10 -o "$INSTALL_DIR/web.zip" "$ZIP_URL" && DOWNLOAD_SUCCESS=1
      fi
  fi

  if [ $DOWNLOAD_SUCCESS -eq 1 ]; then
      echo -e "${GREEN}成功下载前端资源包 ($LATEST_TAG)，正在解压...${NC}"
      
      # 确保安装 unzip
      if ! command -v unzip &> /dev/null; then
          echo -e "${YELLOW}正在安装解压工具...${NC}"
          if [ "$OS_RELEASE" = "alpine" ]; then apk add unzip
          elif command -v apt-get &> /dev/null; then apt-get update && apt-get install -y unzip
          elif command -v yum &> /dev/null; then yum install -y unzip
          fi
      fi
      
      mkdir -p "$INSTALL_DIR/web"
      if unzip -o "$INSTALL_DIR/web.zip" -d "$INSTALL_DIR/web" > /dev/null; then
          rm -f "$INSTALL_DIR/web.zip"
          DOWNLOAD_SUCCESS=1
      else
          echo -e "${RED}解压失败，尝试回退...${NC}"
          rm -f "$INSTALL_DIR/web.zip"
      fi
  fi

  # 兜底方案：如果 web.zip 下载或解压失败，回退到源码 Raw 模式
  if [ $DOWNLOAD_SUCCESS -eq 0 ]; then
      echo -e "${YELLOW}未检测到 Release 资源包，切换到源码同步模式 (Fallback)...${NC}"
      
      # 下载 index.html
      gh_curl -L -f -o "$INSTALL_DIR/web/index.html" "https://raw.githubusercontent.com/$REPO/main/web/index.html"
      
      # 下载 Vite 构建的 assets 目录
      mkdir -p $INSTALL_DIR/web/assets
      ASSETS_URL="https://api.github.com/repos/$REPO/contents/web/assets?ref=main"
      ASSETS_LIST=$(gh_curl -s "$ASSETS_URL" | grep '"name"' | sed -E 's/.*"name": "([^"]+)".*/\1/')
      
      if [ -z "$ASSETS_LIST" ]; then
         echo -e "${RED}警告：无法获取 assets 列表，面板可能无法加载。${NC}"
      else
         for FILE in $ASSETS_LIST; do
            echo -e "${CYAN}  下载 assets/$FILE ...${NC}"
            gh_curl -L -f -o "$INSTALL_DIR/web/assets/$FILE" "https://raw.githubusercontent.com/$REPO/main/web/assets/$FILE"
         done
      fi
  fi

  echo -e "${GREEN}面板资源同步完成！${NC}"
  
  # 修正：移除单引号以支持变量展开
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat > /etc/systemd/system/stealth-controller.service <<EOF
[Unit]
Description=StealthForward Controller Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/stealthforward
ExecStart=/usr/local/bin/stealth-controller
$LICENSE_ENV_LINE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  else
    cat > /etc/init.d/stealth-controller <<EOF
#!/sbin/openrc-run
description="StealthForward Controller Service"
command="/usr/local/bin/stealth-controller"
command_user="root"
directory="/etc/stealthforward"
command_background="yes"
pidfile="/run/stealth-controller.pid"
restart_delay=5

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/stealth-controller
  fi

  service_command daemon-reload
  service_command enable stealth-controller
  service_command start stealth-controller
  echo -e "${GREEN}Controller 安装并启动成功！${NC}"
  echo -e "${CYAN}面板地址: http://你的公网IP:8090/dashboard${NC}"
}

install_agent() {
  # 1. 安装 Nginx（用于托管伪装页和申请证书）
  if command -v nginx &> /dev/null; then
    echo -e "${GREEN}检测到 Nginx 已安装，跳过安装步骤。${NC}"
  else
    echo -e "${YELLOW}正在安装 Nginx (用于伪装页和证书申请)...${NC}"
    if [ "$OS_RELEASE" = "alpine" ]; then
      apk add nginx
    elif command -v apt-get &> /dev/null; then
      apt-get update && apt-get install -y nginx
    elif command -v yum &> /dev/null; then
      yum install -y nginx
    fi
  fi
  service_command enable nginx
  service_command start nginx
  
  # 2. 安装魔改版 Sing-box
  install_sing_box
  
  show_logo
  echo -e "${BLUE}开始安装 StealthForward Agent (入口节点端)...${NC}"
  
  service_command stop stealth-agent 2>/dev/null
  
  mkdir -p $INSTALL_DIR/www
  download_binary "stealth-agent" "stealth-agent"
  
  # 3. 生成并部署伪装页到 Nginx
  echo -e "${CYAN}正在部署伪装页到 Nginx...${NC}"
  if [ -d "/var/www/html" ]; then
    # 如果 Agent 已生成伪装页，复制过去
    if [ -f "$INSTALL_DIR/www/index.html" ]; then
      cp "$INSTALL_DIR/www/index.html" /var/www/html/index.html
    fi
  fi
  
  # 如果环境变量已提供，则跳过交互
  if [ -z "$CTRL_ADDR" ]; then
    read -p "请输入 Controller API 地址 [http://127.0.0.1:8090]: " CTRL_ADDR
  fi
  CTRL_ADDR=${CTRL_ADDR:-http://127.0.0.1:8090}
  
  if [ -z "$NODE_ID" ]; then
    read -p "请输入当前节点 ID [1]: " NODE_ID
  fi
  NODE_ID=${NODE_ID:-1}
  
  if [ -z "$CTRL_TOKEN" ]; then
    read -p "请输入管理口令 (STEALTH_ADMIN_TOKEN) [留空则无需鉴权]: " CTRL_TOKEN
  fi

  # 4. 证书申请流程 (核心改进)
  issue_certificate "$CTRL_DOMAIN"

  if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat > /etc/systemd/system/stealth-agent.service <<EOF
[Unit]
Description=StealthForward Agent Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$BIN_DIR/stealth-agent -controller $CTRL_ADDR -node $NODE_ID -dir $INSTALL_DIR/core -www $INSTALL_DIR/www -token "$CTRL_TOKEN" -fallback-port 8081 -corepath $BIN_DIR/stealth-core -internal
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  else
    cat > /etc/init.d/stealth-agent <<EOF
#!/sbin/openrc-run
description="StealthForward Agent Service"
command="$BIN_DIR/stealth-agent"
command_args="-controller $CTRL_ADDR -node $NODE_ID -dir $INSTALL_DIR/core -www $INSTALL_DIR/www -token $CTRL_TOKEN -fallback-port 8081 -corepath $BIN_DIR/stealth-core -internal"
command_user="root"
command_background="yes"
pidfile="/run/stealth-agent.pid"
restart_delay=10

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/stealth-agent
  fi

  service_command daemon-reload
  service_command enable stealth-agent
  service_command start stealth-agent
  echo -e "${GREEN}Agent 已安装并在后台运行!${NC}"
}

install_ss_exit() {
  show_logo
  echo -e "${BLUE}开始安装 Shadowsocks 落地转发端 (Exit)...${NC}"
  
  # 优先检测本地脚本
  local SCRIPT_PATH="./scripts/ss-install.sh"
  if [ -f "$SCRIPT_PATH" ]; then
    bash "$SCRIPT_PATH"
  else
    # 传递 GH_TOKEN 给子脚本，附加随机数规避 GitHub Raw CDN 缓存
    GH_TOKEN=$GH_TOKEN bash <(gh_curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/ss-install.sh?v=$RANDOM")
  fi
}

uninstall_ss_exit() {
  echo -e "${RED}正在清理 Shadowsocks 落地转发端...${NC}"
  local SCRIPT_PATH="./scripts/ss-install.sh"
  if [ -f "$SCRIPT_PATH" ]; then
    bash "$SCRIPT_PATH" uninstall
  else
    GH_TOKEN=$GH_TOKEN bash <(gh_curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/ss-install.sh?v=$RANDOM") uninstall
  fi
}

uninstall_controller() {
  echo -e "${RED}正在卸载 StealthForward Controller...${NC}"
  service_command stop stealth-controller 2>/dev/null
  service_command disable stealth-controller 2>/dev/null
  rm -f /etc/systemd/system/stealth-controller.service
  rm -f /etc/init.d/stealth-controller
  service_command daemon-reload
  
  rm -f $BIN_DIR/stealth-controller
  rm -f $BIN_DIR/stealth-admin
  # 注意：这里我们询问是否保留数据库
  read -p "是否删除所有数据库和配置数据(不可逆)? [y/N]: " del_data
  if [[ "$del_data" =~ ^[Yy]$ ]]; then
    rm -rf $INSTALL_DIR
    echo -e "${YELLOW}已清除所有配置数据和 SQLite 数据库。${NC}"
  fi
  
  echo -e "${GREEN}Controller 卸载完成！${NC}"
}

uninstall_agent() {
  echo -e "${RED}正在卸载 StealthForward Agent 及相关组件...${NC}"
  
  # 1. 停止并删除 Agent 服务
  service_command stop stealth-agent 2>/dev/null
  service_command disable stealth-agent 2>/dev/null
  rm -f /etc/systemd/system/stealth-agent.service
  rm -f /etc/init.d/stealth-agent
  rm -f $BIN_DIR/stealth-agent
  
  # 2. 停止并删除 Stealth Core (隔离版内核)
  echo -e "${YELLOW}清理 Stealth Core 核心...${NC}"
  service_command stop stealth-core 2>/dev/null
  service_command disable stealth-core 2>/dev/null
  rm -f /etc/systemd/system/stealth-core.service
  rm -f /etc/init.d/stealth-core
  rm -f $BIN_DIR/stealth-core
  rm -rf $INSTALL_DIR/core
  
  # 3. 清理 Nginx 和伪装网站
  read -p "是否卸载 Nginx 并清除伪装网站数据? [y/N]: " del_nginx
  if [[ "$del_nginx" =~ ^[Yy]$ ]]; then
    service_command stop nginx 2>/dev/null
    if [ "$OS_RELEASE" = "alpine" ]; then
      apk del nginx
    elif command -v apt-get &> /dev/null; then
      apt-get purge -y nginx nginx-common
      apt-get autoremove -y
    elif command -v yum &> /dev/null; then
      yum remove -y nginx
    fi
    rm -rf /var/www/html/*
    echo -e "${YELLOW}Nginx 及伪装页已清除。${NC}"
  fi
  
  # 4. 清理主目录
  rm -rf $INSTALL_DIR
  service_command daemon-reload
  
  echo -e "${GREEN}Agent 及其关联组件已彻底清除！${NC}"
}

main_menu() {
  show_logo
  echo -e "1. 安装 ${GREEN}Controller (中控端)${NC}"
  echo -e "2. 安装 ${GREEN}Agent (入口节点端/中转机)${NC}"
  echo -e "3. 安装 ${GREEN}Shadowsocks 落地端 (Exit/落地机)${NC}"
  echo -e "--------------------------------"
  echo -e "4. ${RED}卸载 Controller${NC}"
  echo -e "5. ${RED}卸载 Agent (包含清理内核/伪装页)${NC}"
  echo -e "6. ${RED}卸载 Shadowsocks 落地端${NC}"
  echo -e "--------------------------------"
  echo -e "0. 退出"
  echo ""
  read -p "请选择 [0-6]: " choice

  case $choice in
    1) install_controller ;;
    2) install_agent ;;
    3) install_ss_exit ;;
    4) uninstall_controller ;;
    5) uninstall_agent ;;
    6) uninstall_ss_exit ;;
    0) exit 0 ;;
    *) echo "无效选项" ; sleep 1 ; main_menu ;;
  esac
}

# 根据命令行参数直接运行特定功能，否则进入主菜单
if [ -n "$1" ]; then
  case $1 in
    --update-agent)
      show_logo
      echo -e "${YELLOW}正在更新 Agent...${NC}"
      service_command stop stealth-agent 2>/dev/null
      download_binary "stealth-agent" "stealth-agent" "$2"
      service_command start stealth-agent
      echo -e "${GREEN}Agent 更新完成并不是重启！${NC}"
      ;;
    1) install_controller ;;
    2) install_agent ;;
    3) install_ss_exit ;;
    4) uninstall_controller ;;
    5) uninstall_agent ;;
    6) uninstall_ss_exit ;;
    *) echo "未知参数: $1" ; exit 1 ;;
  esac
else
  main_menu
fi
