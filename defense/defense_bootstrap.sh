#!/bin/bash
# AWD 一键防御加固脚本
# 使用:
#   bash defense_bootstrap.sh user@host:port ssh_password [new_admin_password]
# 示例:
#   bash defense_bootstrap.sh team10@192-168-1-169.pvp7574.bugku.cn:2222 'ssh_pass_here' 'Ad#2026Admin\$ec!'

set -e

TARGET="$1"
SSH_PASS="$2"
ADMIN_PASS="${3:-Ad#2026Admin\$ec!}"

if [ -z "$TARGET" ] || [ -z "$SSH_PASS" ]; then
    echo "Usage: $0 user@host:port ssh_password [new_admin_password]"
    exit 1
fi

USER="${TARGET%%@*}"
HOST_PORT="${TARGET##*@}"
HOST="${HOST_PORT%%:*}"
PORT="${HOST_PORT##*:}"
[ "$PORT" = "$HOST_PORT" ] && PORT="22"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================="
echo "AWD 一键防御加固"
echo "Target: ssh://$USER@$HOST:$PORT"
echo "=========================================="

# ==== Step 0: SSH 密码可用? ====
echo -e "\n[1/6] 检查 SSH 连接..."
if command -v sshpass &>/dev/null; then
    SSH="sshpass -p '$SSH_PASS' ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST"
    SCP="sshpass -p '$SSH_PASS' scp -o StrictHostKeyChecking=no -P $PORT"
else
    SSH="ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST"
    SCP="scp -o StrictHostKeyChecking=no -P $PORT"
fi

eval "$SSH 'echo OK; whoami; id'" || { echo "[X] SSH 连接失败!"; exit 1; }

# ==== Step 1: 上传 WAF 和防御脚本 ====
echo -e "\n[2/8] 上传 WAF + 防御脚本 + IP 防火墙 + 备份/恢复脚本..."
eval "$SCP $SCRIPT_DIR/waf.php $SCRIPT_DIR/backdoor_detector.py $SCRIPT_DIR/flag_protector.py $SCRIPT_DIR/security_harden.py $SCRIPT_DIR/ip_firewall.py $SCRIPT_DIR/traffic_monitor.sh $SCRIPT_DIR/backup.sh $SCRIPT_DIR/restore.sh $USER@$HOST:/tmp/"
eval "$SSH 'ls -la /tmp/waf.php /tmp/backdoor_detector.py /tmp/ip_firewall.py /tmp/traffic_monitor.sh /tmp/backup.sh /tmp/restore.sh'"
chmod +x "$SCRIPT_DIR/traffic_monitor.sh" "$SCRIPT_DIR/backup.sh" "$SCRIPT_DIR/restore.sh" 2>/dev/null || true
eval "$SSH 'chmod +x /tmp/traffic_monitor.sh /tmp/ip_firewall.py /tmp/backup.sh /tmp/restore.sh'"

# ==== Step 1.5: 拿到靶机第一件事 —— 立刻完整备份 (止损底牌) ====
echo -e "\n[2.5/8] ⚡ 立刻完整备份 (拿到靶机第一件事, 止损底牌)"
eval "$SSH '
export AWD_BACKUP_DIR=/tmp/awd_backup
export AWD_WEB_ROOT=/app
export AWD_DB_NAME=xyhcms
export AWD_DB_USER=cms
bash /tmp/backup.sh full 2>&1 | tail -8
'"
echo "   💡 后续任何操作出问题, 都可以用 /tmp/restore.sh all 秒级回滚到这一刻"

# ==== Step 2: 部署 WAF (index.php/xyhai.php 顶部加载) ====
echo -e "\n[3/8] 部署 WAF..."
eval "$SSH 'sudo cp /tmp/waf.php /app/waf.php || cp /tmp/waf.php /app/waf.php
chmod 644 /app/waf.php 2>/dev/null
# 在所有入口文件顶部 require waf.php
for entry in /app/index.php /app/xyhai.php /app/admin.php /app/Home/entry.php; do
  if [ -f \"\$entry\" ] && ! head -1 \"\$entry\" | grep -q waf.php; then
    sed -i \"1i\\<?php require_once '/app/waf.php'; ?>\\n\" \"\$entry\" 2>/dev/null || \
    python3 -c \"import sys; p=sys.argv[1]; c=open(p).read(); open(p,'w').write(\\\"<?php require_once '/app/waf.php'; ?>\\n\\\"+c[6:] if c.startswith(\\\"<?php\\\") else \\\"<?php require_once '/app/waf.php'; ?>\\n\\\"+c)\" \"\$entry\" 2>/dev/null
  fi
done
echo WAF deployed'"

# ==== Step 3: 部署 IP 防火墙 (默认 deny, 白名单模式) ====
echo -e "\n[4/8] 部署 IP 防火墙 (白名单模式: 默认 deny, 除了本机/SSH客户端/127.0.0.1 全部拦截)..."
# 拿到 SSH 连接的客户端 IP (从 SSH_CONNECTION 或 who am i 获取，以便加入白名单)
SSH_CLIENT_IP=""
if command -v sshpass &>/dev/null; then
  SSH_CLIENT_IP=$(eval "$SSH \"echo \\\$SSH_CLIENT\" | awk '{print \$1}'")
fi
[ -z "$SSH_CLIENT_IP" ] && SSH_CLIENT_IP=$(eval "$SSH 'who am i 2>/dev/null' | grep -oE '\\([0-9.]+\\)' | tr -d '()' | head -1")
[ -z "$SSH_CLIENT_IP" ] && SSH_CLIENT_IP="$(echo $SSH_CLIENT | awk '{print $1}')"
[ -z "$SSH_CLIENT_IP" ] && SSH_CLIENT_IP="127.0.0.1"
echo "   客户端 SSH IP: $SSH_CLIENT_IP → 自动加入白名单"

eval "$SSH '
IPFW=/tmp/ip_firewall.py
export AWD_IPFW_DIR=/tmp/awd_ipfw

# 初始化 + 添加默认白名单
python3 \$IPFW init
# 1) 本机回环 / 自己 IP
python3 \$IPFW add white 127.0.0.1 "localhost"
python3 \$IPFW add white ::1 "ipv6-loopback"
python3 \$IPFW add white $(hostname -I 2>/dev/null | awk "{print \$1}" || echo 127.0.0.1) "本机网卡IP"
# 2) SSH 客户端 IP (我方管理机)
python3 \$IPFW add white \"'"$SSH_CLIENT_IP"'\" "AWD管理机 SSH 客户端"

# 3) 检测比赛平台 flag_server/checker 的 IP
#    - 从已有的 access.log 中找最近的 2xx/3xx 除自己外最多的 IP
CHECKER_IP=""
for lg in /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log; do
  if [ -f \"\$lg\" ]; then
    CAND=\$(awk \"{print \\$1}\" \"\$lg\" 2>/dev/null | sort | uniq -c | sort -rn | head -3 | awk \"{print \\$2}\")
    for cand in \$CAND; do
      if [ \"\$cand\" != \"'"$SSH_CLIENT_IP"'\" ] && [ \"\$cand\" != \"127.0.0.1\" ]; then
        CHECKER_IP=\"\$cand\"
        break 2
      fi
    done
  fi
done
if [ -n \"\$CHECKER_IP\" ]; then
  python3 \$IPFW add white \"\$CHECKER_IP\" \"疑似比赛平台 checker (历史访问最多IP)\"
  echo \"   checker 候选IP: \$CHECKER_IP 已自动加入白名单\"
fi

# 生成: waf.php 要 include 的 PHP 规则文件
python3 \$IPFW generate waf --out \$AWD_IPFW_DIR/ip_firewall.php
# 生成: Apache .htaccess (放在 Web 根)
python3 \$IPFW generate htaccess --out /app/.htaccess 2>/dev/null || true
# 生成: iptables 脚本
python3 \$IPFW generate iptables --out /tmp/awd_ipfw_rules.sh 2>/dev/null || true
chmod +x /tmp/awd_ipfw_rules.sh 2>/dev/null
# 安全阀: 应用 iptables (默认 deny) 前, 必须确认白名单已含 SSH 管理机 IP
# 否则会把自己 SSH 也封断导致失联!
echo ---安全检查: 白名单是否已含管理机IP---
SSH_IN_WL=\$(python3 \$IPFW check \"'"$SSH_CLIENT_IP"'\" 2>/dev/null | grep -c "ALLOW")
if [ \"\$SSH_IN_WL\" -ge 1 ]; then
  echo \"  [安全] 管理机 IP '$SSH_CLIENT_IP' 已在白名单 (ALLOW), 可以应用 iptables\"
  echo ---应用 iptables 规则---
  bash /tmp/awd_ipfw_rules.sh 2>&1 | tail -3 || echo \"   iptables 需要更高权限, 降级用 WAF + htaccess 层即可\"
else
  echo \"  [!!!] 管理机 IP '$SSH_CLIENT_IP' 未在 ALLOW 白名单! 为防止误封失联, 跳过 iptables 应用。\"
  echo \"  [!!!] 默认 deny 未启用 L1 层, 仅 WAF/htaccess 层生效。\"
  echo \"  [!!!] 如需启用: 先 python3 /tmp/ip_firewall.py add white <管理机IP> 再手动 bash /tmp/awd_ipfw_rules.sh\"
fi

echo ---白名单摘要---
python3 \$IPFW list | head -20
'"

# ==== Step 4: 清理后门 ====
echo -e "\n[5/8] 清理后门 (webshell/crontab/authorized_keys/进程)..."
eval "$SSH '
# 清 authorized_keys
> ~/.ssh/authorized_keys 2>/dev/null
chmod 700 ~/.ssh 2>/dev/null; chmod 600 ~/.ssh/authorized_keys 2>/dev/null

# 清 crontab (保留 defense 任务)
crontab -l 2>/dev/null > /tmp/cr.bak
grep -E \"backdoor|defense|scan|rotate|waf|ipfw|traffic|flag_prot\" /tmp/cr.bak > /tmp/cr.new 2>/dev/null || true
crontab /tmp/cr.new 2>/dev/null || true

# 杀可疑进程 (非 sshd/nginx/mysqld/php-fpm)
ps -eo pid,comm,args | grep -vE \"sshd|nginx|mysqld|mariadbd|php-fpm|systemd|init|crond|bash|python|rsyslog|dbus|ps |grep\" | awk \"NR>1 {print \\$1}\" | while read p; do
  if [ -n \"\$p\" ] && kill -0 \"\$p\" 2>/dev/null; then kill -9 \"\$p\" 2>/dev/null; fi
done

# 扫 webshell
python3 /tmp/backdoor_detector.py /app 2>&1 | grep -E \"FOUND|可疑|检测到\" || echo no-webshell

# 删除安装目录/泄露文件
rm -rf /app/Install /app/.git /app/.svn /app/.DS_Store 2>/dev/null

# 上传目录禁 PHP
for d in /app/upload /app/uploads /app/avatar /app/Public/upload; do
  mkdir -p \"\$d\"
  echo \"php_flag engine off\" > \"\$d/.htaccess\" 2>/dev/null || true
done
echo CLEANED'"

# ==== Step 5: 修改密码 (数据库/后台/Key, 不动 SSH) ====
echo -e "\n[6/8] 修改密码 (SSH 不动!)"
DB_PASS="Xy#2026Db\$ecure!"
ADMIN_PASS2="${ADMIN_PASS}"
COOKIE_KEY="Ck#2026\$ecretKey!!"
EMAIL_PASS="Em#2026Mail\$ec!!"

eval "$SSH '
# 用 PHP 脚本改 (避免 $ 被 bash 解析)
cat > /tmp/fix_pass.php <<\"PHPEOF\"
<?php
\$dbpass = \"'"$DB_PASS"'\";
\$adminpass = \"'"$ADMIN_PASS2"'\";
\$cookie = \"'"$COOKIE_KEY"'\";
\$email = \"'"$EMAIL_PASS"'\";

// 1. config/db.php
foreach ([\"/app/App/Common/Conf/db.php\", \"/app/Common/Conf/db.php\", \"/app/config/db.php\"] as \$f) {
    if (file_exists(\$f)) {
        \$c = file_get_contents(\$f);
        \$c = preg_replace(\"/DB_PWD.*/\", \"DB_PWD\\' => \\'\".\$dbpass.\"\\',\", \$c);
        \$c = preg_replace(\"/password[^,]*\", \"password\\' => \\'\".\$dbpass.\"\\'\", \$c);
        file_put_contents(\$f, \$c);
        echo \"DB: \$f updated\\n\";
    }
}
// 2. 后台密码
chdir(\"/app\");
// 查找 user 表
try {
    \$m = new PDO(\"mysql:host=localhost;dbname=xyhcms\",\"cms\",\$dbpass);
    \$salt = substr(md5(uniqid()),0,6);
    \$pass = md5(md5(\$adminpass).\$salt);
    \$m->exec(\"UPDATE xy_admin SET password=\\'\".\$pass.\"\\',salt=\\'\".\$salt.\"\\' WHERE id=1 LIMIT 1\");
    echo \"Admin password updated (salt=\$salt)\\n\";
} catch (Exception \$e) { echo \"Admin fail: \".\$e->getMessage().\"\\n\"; }
PHPEOF
php /tmp/fix_pass.php

# 3. Cookie Key / 其他
for cf in /app/App/Common/Conf/config.php /app/Common/Conf/config.php /app/config.php; do
  if [ -f \"\$cf\" ]; then
    sed -i \"s/TOKEN.*/TOKEN\\x27 => \\x27${COOKIE_KEY}\\x27,/g\" \"\$cf\" 2>/dev/null || true
  fi
done
echo PASSWORDS_DONE'"

# ==== Step 6: 部署计划任务 (每1分钟扫马 + 每5分钟加密flag + 每5分钟增量备份 + 流量监控守护) ====
echo -e "\n[7/8] 部署计划任务 + 流量监控守护进程"
eval "$SSH '
cat > /tmp/awd_auto_defense.sh <<SHEOF
#!/bin/bash
LOG=/tmp/awd_defense.log
echo ---\"\$(date)\"--- >> \$LOG
# 扫马
python3 /tmp/backdoor_detector.py /app >> \$LOG 2>&1
# 文件权限
chmod 640 /app/App/Common/Conf/db.php /app/App/Common/Conf/config.php 2>/dev/null
chmod 640 /app/Common/Conf/*.php 2>/dev/null
# 清 /tmp
find /tmp -name \"*.php\" -mmin +60 -delete 2>/dev/null
# 再清授权文件
> ~/.ssh/authorized_keys
# IP防火墙: 重新生成规则并应用 (保证新加入的黑名单/白名单实时生效)
export AWD_IPFW_DIR=/tmp/awd_ipfw
python3 /tmp/ip_firewall.py generate waf --out \$AWD_IPFW_DIR/ip_firewall.php >> \$LOG 2>&1
python3 /tmp/ip_firewall.py generate htaccess --out /app/.htaccess >> \$LOG 2>&1
# WAF 自动拉黑列表合并到 ip_firewall
if [ -f \"\$AWD_IPFW_DIR/waf_blacklist_auto.txt\" ]; then
  sort -u -k2,2 \"\$AWD_IPFW_DIR/waf_blacklist_auto.txt\" 2>/dev/null | while read ts ip reason; do
    [ -n \"\$ip\" ] && python3 /tmp/ip_firewall.py add black \"\$ip\" \"waf_auto:\$reason\" >> \$LOG 2>&1
  done
  > \"\$AWD_IPFW_DIR/waf_blacklist_auto.txt\"
fi
SHEOF
chmod +x /tmp/awd_auto_defense.sh

# 安装 crontab
(crontab -l 2>/dev/null; echo \"*/1 * * * * /tmp/awd_auto_defense.sh >> /tmp/awd_defense.log 2>&1\") | crontab -
(crontab -l 2>/dev/null; echo "*/5 * * * * python3 /tmp/flag_protector.py protect aes >> /tmp/awd_defense.log 2>&1") | crontab -
# ⭐ 每5分钟增量备份 (只打包最近10分钟变更的文件, 极快)
(crontab -l 2>/dev/null; echo \"*/5 * * * * AWD_BACKUP_DIR=/tmp/awd_backup AWD_WEB_ROOT=/app AWD_DB_NAME=xyhcms AWD_DB_USER=cms bash /tmp/backup.sh inc >> /tmp/awd_defense.log 2>&1\") | crontab -
# 每小时清理一次旧备份 (只保留最新 20 份, 防磁盘满)
(crontab -l 2>/dev/null; echo \"0 * * * * bash /tmp/backup.sh purge 20 >> /tmp/awd_defense.log 2>&1\") | crontab -

# 尝试启动流量监控 (后台 daemon, 有 access.log 就跑)
LOGS=\"\"
for lg in /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log; do
  [ -f \"\$lg\" ] && LOGS=\"\$LOGS \$lg\"
done
if [ -n \"\$LOGS\" ]; then
  echo ---启动流量监控, 监控路径: \$LOGS---
  AWD_IPFW_DIR=/tmp/awd_ipfw RATE_MAX_HITS=40 RATE_WINDOW_SEC=10 /tmp/traffic_monitor.sh daemon \"\$LOGS\" combined
fi
echo 当前 crontab:
crontab -l'"

# ==== Step 7: 验证防护 ====
echo -e "\n[8/8] 验证防护效果..."
echo "   [1] WAF 攻击特征拦截测试 (TP RCE / SQLi 应该 403)"
for path in "" "index.php?s=/Index/index/name/\${@print(md5(1234))}" "index.php?id=1'%20union%20select%201,2,3--"; do
    st=$(eval "$SSH \"curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1/$path' 2>/dev/null\"")
    echo "     [$st] /$path"
done
echo ""
echo "   [2] IP 白名单验证 (127.0.0.1 是白名单 → 应该 200/302; 伪造外部IP 应该 403)"
# 127.0.0.1 应该 2xx/3xx
st=$(eval "$SSH \"curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1/' 2>/dev/null\"")
echo "     本机127.0.0.1 → [$st]"
# 伪造 X-Forwarded-For: 非白名单 IP，WAF 层会识别并 403
st=$(eval "$SSH \"curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 1.2.3.4' 'http://127.0.0.1/' 2>/dev/null\"")
echo "     伪造非白名单 X-Forwarded-For:1.2.3.4 → [$st]  (期望 403=IP 拦截生效)"
# 伪造命中 WAF 规则 + 非白IP, 确认 403
st=$(eval "$SSH \"curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 10.20.30.40' 'http://127.0.0.1/index.php?id=1%27%20or%201=1--' 2>/dev/null\"")
echo "     非白IP+SQLi payload → [$st]  (期望 403=双重拦截)"

echo ""
echo "=== 💡 要添加攻击机/管理机到白名单（务必执行，否则你自己会被封！）==="
echo "   在目标靶机上执行:"
echo "     python3 /tmp/ip_firewall.py add white <你的攻击机IP> \"我的攻击机\""
echo "     python3 /tmp/ip_firewall.py generate waf --out /tmp/awd_ipfw/ip_firewall.php"
echo "     python3 /tmp/ip_firewall.py generate htaccess --out /app/.htaccess"
echo "     bash /tmp/awd_ipfw_rules.sh   # 应用到iptables (可选)"
echo ""
echo "=== 💡 查看当前被封的 IP & 最近拦截日志 ==="
echo "     python3 /tmp/ip_firewall.py list"
echo "     tail -n 30 /tmp/awd_ipfw/ban.log"
echo ""
echo "=== 💡 临时关闭 IP deny (仅 WAF 特征模式) - 误封应急 ==="
echo "     export AWD_WAF_DEFAULT_POLICY=allow"
echo "     sed -i \"s|default_policy.*deny|default_policy\\\": \\\"allow|\" /tmp/awd_ipfw/ip_rules.json"

echo -e "\n=========================================="
echo "全部完成! 日志位置: /tmp/awd_defense.log"
echo "IP 规则存储:   /tmp/awd_ipfw/ip_rules.json"
echo "封禁日志:      /tmp/awd_ipfw/ban.log"
echo "监控状态:      bash /tmp/traffic_monitor.sh status"
echo ""
echo "=== 💾 备份与恢复 (止损底牌) ==="
echo "  备份目录:     /tmp/awd_backup/  (latest → 最新)"
echo "  列出备份:     bash /tmp/backup.sh list"
echo "  手动备份:     bash /tmp/backup.sh full   (完整)  /  bash /tmp/backup.sh inc  (增量)"
echo "  校验备份:     bash /tmp/backup.sh verify"
echo "  💥 紧急恢复:  bash /tmp/restore.sh all            (服务宕机时秒级止损)"
echo "  对比篡改:     bash /tmp/restore.sh diff           (查谁改了什么)"
echo "  健康检查:     bash /tmp/restore.sh health"
echo "=========================================="
