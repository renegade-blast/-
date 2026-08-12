#!/bin/bash
# AWD 快速初始化脚本
# 一键完成: 扫描环境 -> 加固 -> 启动监控

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    echo -e "${GREEN}=== AWD 快速初始化脚本 ===${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] 请使用 root 权限运行${NC}"
        exit 1
    fi
}

scan_system() {
    echo -e "${YELLOW}[*] 系统信息扫描${NC}"
    echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "  Kernel: $(uname -r)"
    echo "  IP: $(hostname -I 2>/dev/null || ip addr show | grep 'inet ' | awk '{print $2}')"
    echo "  Hostname: $(hostname)"
    echo ""

    echo -e "${YELLOW}[*] 服务检测${NC}"
    for svc in apache2 nginx mysql sshd redis-server mongod docker; do
        if systemctl is-active --quiet $svc 2>/dev/null; then
            echo -e "  ${GREEN}[+]${NC} $svc 运行中"
        else
            echo -e "  ${RED}[-]${NC} $svc 未运行"
        fi
    done
    echo ""

    echo -e "${YELLOW}[*] 敏感端口检测${NC}"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""

    echo -e "${YELLOW}[*] 可疑进程检测${NC}"
    ps aux | grep -E '(minerd|xmrig|kinsing|cryptonight)' | grep -v grep || echo "  无可疑进程"
    echo ""

    echo -e "${YELLOW}[*] 可疑 crontab 检测${NC}"
    crontab -l 2>/dev/null || echo "  无 crontab"
    cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' || echo "  /etc/crontab 无异常"
    echo ""

    echo -e "${YELLOW}[*] /tmp 目录检测${NC}"
    ls -la /tmp/ 2>/dev/null | head -20
    echo ""
}

harden_system() {
    echo -e "${YELLOW}[*] 执行系统加固${NC}"

    # SSH 加固
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        echo -e "  ${GREEN}[+]${NC} SSH 加固完成"
    fi

    # 清除可疑计划任务
    crontab -r 2>/dev/null || true
    echo -e "  ${GREEN}[+]${NC} 可疑 crontab 已清除"

    # 限制 /tmp 执行
    mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null || true
    echo -e "  ${GREEN}[+]${NC} /tmp 执行限制"

    # 更新防火墙规则
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -j DROP
    echo -e "  ${GREEN}[+]${NC} 防火墙规则已更新"

    echo ""
}

monitor_system() {
    echo -e "${YELLOW}[*] 启动实时监控${NC}"

    # 监控脚本
    cat > /tmp/awd_monitor.sh << 'MONITOR_EOF'
#!/bin/bash
while true; do
    # 查杀挖矿进程
    for proc in minerd xmrig cryptonight kinsing kdevtmpfsi; do
        pkill -f "$proc" 2>/dev/null
    done

    # 检查 /etc/passwd 是否被篡改
    if ! grep -q 'root:x:' /etc/passwd 2>/dev/null; then
        echo "[ALERT] /etc/passwd 可能被篡改!" >> /tmp/awd_alerts.log
    fi

    # 检查 crontab
    if [ -f /etc/crontab ]; then
        grep -v '^#' /etc/crontab | grep -v '^$' > /tmp/crontab_current
        diff /tmp/crontab_backup /tmp/crontab_current > /dev/null 2>&1 || {
            echo "[ALERT] crontab 发生变化!" >> /tmp/awd_alerts.log
        }
    fi

    sleep 10
done
MONITOR_EOF

    chmod +x /tmp/awd_monitor.sh
    nohup /tmp/awd_monitor.sh > /dev/null 2>&1 &
    echo -e "  ${GREEN}[+]${NC} 监控进程已启动 (PID: $!)"
    echo ""
}

start_web_defense() {
    echo -e "${YELLOW}[*] Web 应用加固${NC}"

    if [ -d /var/www/html ]; then
        # PHP 禁用危险函数
        for ini_file in /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini; do
            if [ -f "$ini_file" ]; then
                sed -i 's/^disable_functions.*/disable_functions = system,exec,shell_exec,passthru,proc_open,pcntl_exec,popen/' "$ini_file"
                sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$ini_file"
                sed -i 's/^expose_php.*/expose_php = Off/' "$ini_file"
                echo -e "  ${GREEN}[+]${NC} $ini_file 加固完成"
            fi
        done
    fi
    echo ""
}

main() {
    banner
    check_root
    scan_system

    echo -e "${GREEN}选择操作:${NC}"
    echo "  1) 仅扫描"
    echo "  2) 扫描 + 加固"
    echo "  3) 扫描 + 加固 + 监控 + Web防御 (全选)"
    echo -n "请输入 [1-3]: "
    read choice

    case $choice in
        1)
            ;;
        2)
            harden_system
            ;;
        3)
            harden_system
            monitor_system
            start_web_defense
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}=== 操作完成 ===${NC}"
}

main
