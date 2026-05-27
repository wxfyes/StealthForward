#!/bin/bash
# StealthForward - 落地机专用 Shadowsocks 一键安装脚本 (全能版)
# 支持自定义端口、NAT 映射、多后端共存

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

function install_ss() {
    echo -e "${BLUE}==================================================${PLAIN}"
    echo -e "${BLUE}     StealthForward 落地机助手 (全能版)           ${PLAIN}"
    echo -e "${BLUE}==================================================${PLAIN}"

    # 1. 选择加密方式
    echo -e "1. 选择加密方式:"
    echo -e "  ${GREEN}1)${PLAIN} chacha20-ietf-poly1305 (默认)"
    echo -e "  ${GREEN}2)${PLAIN} 2022-blake3-aes-128-gcm"
    echo -e "  ${GREEN}3)${PLAIN} aes-256-gcm"
    read -p "请输入序号 [1-3, 默认 1]: " choice
    case $choice in
        2) METHOD="2022-blake3-aes-128-gcm" ;;
        3) METHOD="aes-256-gcm" ;;
        *) METHOD="chacha20-ietf-poly1305" ;;
    esac

    # 2. 自定义端口
    RANDOM_PORT=$((RANDOM % 10000 + 20000))
    echo -e "\n2. 配置监听端口 (NAT 机器请填写内网转发端口):"
    read -p "请输入端口 [默认 23036]: " PORT
    [ -z "$PORT" ] && PORT=23036

    # 依赖检查与安装 (兼容 Alpine/Ubuntu/CentOS)
    if ! command -v openssl &> /dev/null; then
        echo -e "${YELLOW}检测到缺少 openssl，正在尝试自动安装...${PLAIN}"
        if command -v apk &> /dev/null; then
            apk update && apk add openssl
        elif command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y openssl
        elif command -v yum &> /dev/null; then
            yum install -y openssl
        fi
    fi

    # 3. 智能探测内核 (避开管理脚本，寻找真正的二进制)
    SB_BIN=""
    SB_TYPE="native" # 默认为原生 sing-box

    # 优先检测二进制路径，并且通过实际试运行验证其是否可用 (防止在 Alpine 等系统上因为动态链接缺失报 not found 误判)
    POTENTIAL_BINS=("/usr/local/tox/tox" "/usr/local/V2bX/V2bX" "/usr/bin/sing-box" "/usr/local/bin/sing-box")
    
    for bin in "${POTENTIAL_BINS[@]}"; do
        if [ -f "$bin" ] && [ -x "$bin" ]; then
            # 实际试运行以检查动态库依赖是否满足
            if ! "$bin" version &>/dev/null; then
                continue
            fi
            if "$bin" version 2>&1 | grep -qiE "tox|V2bX"; then
                SB_BIN="$bin"
                SB_TYPE="v2bx"
                break
            fi
            if "$bin" version 2>&1 | grep -qi "sing-box"; then
                SB_BIN="$bin"
                SB_TYPE="native"
                break
            fi
        fi
    done

    if [ -z "$SB_BIN" ]; then
        # 兜底检测 (同样必须试运行测试，避免 command -v 误判因 libc 缺失而无法执行的残留二进制)
        if command -v sing-box &> /dev/null && "$(command -v sing-box)" version &>/dev/null; then
            SB_BIN=$(command -v sing-box)
            SB_TYPE="native"
        elif command -v tox &> /dev/null && [ ! -f /usr/bin/tox ] && "$(command -v tox)" version &>/dev/null; then
            SB_BIN=$(command -v tox)
            SB_TYPE="v2bx"
        fi
    fi

    if [ -n "$SB_BIN" ]; then
        echo -e "${GREEN}已锁定核心: $SB_BIN (模式: $SB_TYPE)${PLAIN}"
    else
        echo -e "${BLUE}未检测到兼容核心，正在为您安装隔离版内核...${PLAIN}"
        
        # 1. 如果是 Alpine 系统，优先尝试直接从 Alpine 社区源安装原生编译版本 (天然支持 musl libc)
        if command -v apk &> /dev/null; then
            echo -e "${YELLOW}检测到 Alpine 环境，尝试安装官方原生 musl-compatible 核心...${PLAIN}"
            # 尝试启用 community 源并安装
            apk add sing-box --no-cache || true
            if command -v sing-box &> /dev/null; then
                SB_BIN=$(command -v sing-box)
            fi
        fi

        # 2. 如果包管理器没有装上，再尝试官方一键安装脚本
        if [ -z "$SB_BIN" ]; then
            if bash <(curl -fsSL https://sing-box.app/install.sh) 2>/dev/null && command -v sing-box &>/dev/null; then
                SB_BIN=$(command -v sing-box)
            fi
        fi

        # 3. 官方脚本失败时，启用稳健的静态二进制下载兜底（完美支持 Alpine / NAT 小鸡）
        if [ -z "$SB_BIN" ]; then
            echo -e "${YELLOW}官方安装途径均不可用，正在通过静态二进制压缩包进行兜底安装...${PLAIN}"
            
            # 如果是 Alpine 系统，且我们要运行编译好的 glibc 静态包，必须补齐 gcompat 库支持
            if command -v apk &> /dev/null; then
                echo -e "${YELLOW}由于是 Alpine 环境，正在自动补齐 glibc 兼容层 (gcompat) 以支持二进制执行...${PLAIN}"
                apk add gcompat --no-cache || true
            fi

            ARCH=$(uname -m)
            URL_ARCH="amd64"
            if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
                URL_ARCH="arm64"
            elif [ "$ARCH" = "s390x" ]; then
                URL_ARCH="s390x"
            elif [ "$ARCH" = "riscv64" ]; then
                URL_ARCH="riscv64"
            fi
            
            VERSION="1.13.12"
            TEMP_DIR="/tmp/singbox_install"
            mkdir -p $TEMP_DIR
            
            echo -e "${BLUE}正在下载 sing-box v${VERSION} (${URL_ARCH}) 静态二进制...${PLAIN}"
            DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${URL_ARCH}.tar.gz"
            
            if curl -Lo "$TEMP_DIR/sing-box.tar.gz" "$DOWNLOAD_URL" || wget -O "$TEMP_DIR/sing-box.tar.gz" "$DOWNLOAD_URL"; then
                tar -zxf "$TEMP_DIR/sing-box.tar.gz" -C "$TEMP_DIR"
                EXTRACTED_BIN=$(find "$TEMP_DIR" -type f -name "sing-box" | head -n 1)
                if [ -n "$EXTRACTED_BIN" ]; then
                    mv -f "$EXTRACTED_BIN" /usr/bin/sing-box
                    chmod +x /usr/bin/sing-box
                    echo -e "${GREEN}静态内核安装成功：/usr/bin/sing-box${PLAIN}"
                    SB_BIN="/usr/bin/sing-box"
                else
                    echo -e "${RED}解压后未找到二进制文件！${PLAIN}"
                fi
            else
                echo -e "${RED}下载 sing-box 静态二进制失败，请检查网络！${PLAIN}"
            fi
            rm -rf $TEMP_DIR
        fi
        
        if [ -z "$SB_BIN" ] || [ ! -f "$SB_BIN" ]; then
            echo -e "${RED}内核安装失败，无法继续，请检查系统环境或手动安装 sing-box。${PLAIN}"
            exit 1
        fi
        SB_TYPE="native"
    fi

    # 4. 隔离配置环境
    CONF_DIR="/etc/stealth-ss"
    RAW_CONF="$CONF_DIR/raw.json"
    WRAPPER_CONF="$CONF_DIR/config.json"
    mkdir -p $CONF_DIR

    # 5. 生成密钥
    PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)

    # 6. 写入原生 Sing-box 格式配置
    cat > $RAW_CONF <<EOF
{
  "log": { "level": "error" },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": $PORT,
      "method": "$METHOD",
      "password": "$PASSWORD"
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF

    # 7. 如果是 v2bx/tox 模式，生成包装配置
    if [ "$SB_TYPE" == "v2bx" ]; then
        cat > $WRAPPER_CONF <<EOF
{
  "Log": { "Level": "error" },
  "Cores": [
    {
      "Type": "sing",
      "Name": "stealth",
      "OriginalPath": "$RAW_CONF"
    }
  ],
  "Nodes": []
}
EOF
        START_CMD="$SB_BIN server -c $WRAPPER_CONF"
    else
        cp $RAW_CONF $WRAPPER_CONF
        START_CMD="$SB_BIN run -c $WRAPPER_CONF"
    fi

    # 8. 创建并启动服务
    if command -v systemctl &> /dev/null; then
        cat > /etc/systemd/system/stealth-ss.service <<EOF
[Unit]
Description=StealthForward SS Exit Service
After=network.target nss-lookup.target

[Service]
ExecStart=$START_CMD
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable stealth-ss
        systemctl restart stealth-ss
    else
        pkill -f "$WRAPPER_CONF" || true
        nohup $START_CMD > /dev/null 2>&1 &
    fi

    # 8. 获取公网 IP
    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org || echo "您的公网IP")

    echo -e "\n${GREEN}==================================================${PLAIN}"
    echo -e "${GREEN}🎉 落地机服务已启动 (隔离共存模式) ${PLAIN}"
    echo -e "${GREEN}==================================================${PLAIN}"
    echo -e "${BLUE}落地机地址:   ${PLAIN}$IP"
    echo -e "${BLUE}内网监听端口: ${PLAIN}$PORT"
    echo -e "${BLUE}加密方式:     ${PLAIN}$METHOD"
    echo -e "${BLUE}连接密码:     ${PLAIN}$PASSWORD"
    echo -e "${GREEN}==================================================${PLAIN}"
    echo -e "${YELLOW}NAT 机器提醒：请确保已在服务商后台将公网端口映射至内网端 $PORT${PLAIN}"
    echo -e "${GREEN}==================================================${PLAIN}\n"
}

function uninstall_ss() {
    echo -e "${RED}正在卸载 StealthForward SS 落地服务...${PLAIN}"
    if command -v systemctl &> /dev/null; then
        systemctl stop stealth-ss || true
        systemctl disable stealth-ss || true
        rm -f /etc/systemd/system/stealth-ss.service
        systemctl daemon-reload
    else
        pkill -f "etc/stealth-ss/config.json" || true
    fi
    rm -rf /etc/stealth-ss
    echo -e "${GREEN}卸载完成！${PLAIN}"
}

# 脚本入口
case "$1" in
    uninstall)
        uninstall_ss
        ;;
    *)
        install_ss
        ;;
esac
