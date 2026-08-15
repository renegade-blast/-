#!/bin/bash
# AWD 后台隐藏文件扫描 + 定时监控 + 自动改密
# 用法: bash awd_auto_defense.sh [start|stop|status|scan|changepass]

TARGET_HOST="192-168-1-169.pvp7574.bugku.cn"
SSH_PORT="2222"
SSH_USER="team10"
# 密码从环境变量注入, 防止明文入库: AWD_SSH_PASS=xxx bash auto_defense.sh
SSH_PASS="${AWD_SSH_PASS:-}"

ACTION=${1:-start}
REMOTE_DIR="/app"
LOG_DIR="/tmp/awd_auto"
PID_FILE="/tmp/awd_auto_pids.txt"

mkdir -p "$LOG_DIR"

# ====================== 远程脚本 ======================
# 1. 后台隐藏文件扫描脚本 (每1分钟)
read -r -d '' SCAN_SCRIPT << 'SCANEOF'
#!/bin/bash
# 后台隐藏文件扫描 - 每60秒
LOG="/tmp/awd_hidden_scan.log"
BASELINE="/tmp/awd_file_baseline.txt"
echo "=== 扫描启动 $(date) ===" >> $LOG

while true; do
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    # 扫描所有 .php/.htaccess/.user.ini 等隐藏文件
    CURRENT=$(find /app -type f \( -name "*.php" -o -name ".htaccess" -o -name ".user.ini" -o -name "*.phtml" -o -name "*.phar" -o -name "*.php3" -o -name "*.php5" -o -name "*.pht" \) -printf "%p %s %T@\n" 2>/dev/null | sort)

    # 1. 与基线对比 - 发现新增/修改文件
    if [ -f "$BASELINE" ]; then
        DIFF=$(diff <(cat "$BASELINE") <(echo "$CURRENT") | grep "^>" | sed 's/^> //')
        if [ -n "$DIFF" ]; then
            echo "[$TS] [!] 文件变化:" >> $LOG
            echo "$DIFF" >> $LOG
            # 检查变化文件是否含木马特征
            echo "$DIFF" | awk '{print $1}' | while read f; do
                [ -f "$f" ] || continue
                if grep -qlE "eval\s*\(\s*\$_(POST|GET|REQUEST)|(system|exec|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST)|assert\s*\(\s*\$_(POST|GET|REQUEST)|(eval|assert|system)\s*\(\s*base64_decode|create_function\s*\(" "$f" 2>/dev/null; then
                    echo "[$TS] [木马] $f -> 隔离" >> $LOG
                    mv "$f" "/tmp/awd_quarantine/$(basename $f).$(date +%s)" 2>/dev/null
                fi
            done
        fi
    else
        echo "$CURRENT" > "$BASELINE"
        echo "[$TS] [+] 基线已建立 ($(echo "$CURRENT" | wc -l) 个文件)" >> $LOG
    fi

    # 2. 扫描可疑文件名 (常见后门命名)
    SUSPECT=$(find /app -type f \( -name ".*" -o -name "*.php.bak" -o -name "*.php.old" -o -name "*~" -o -name "test*.php" -o -name "tmp*.php" -o -name "shell*.php" -o -name "cmd*.php" -o -name "1.php" -o -name "0.php" -o -name "x.php" -o -name "c.php" -o -name "c99*" -o -name "r57*" \) 2>/dev/null | grep -v ".awd_security" | grep -v "Runtime")
    if [ -n "$SUSPECT" ]; then
        echo "[$TS] [可疑文件]" >> $LOG
        echo "$SUSPECT" >> $LOG
    fi

    # 3. 检查 upload 目录下的 PHP 文件
    UPLOAD_PHP=$(find /app/uploads /app/avatar /app/Data -name "*.php" -type f 2>/dev/null)
    if [ -n "$UPLOAD_PHP" ]; then
        echo "[$TS] [上传目录PHP]" >> $LOG
        echo "$UPLOAD_PHP" >> $LOG
        echo "$UPLOAD_PHP" | while read f; do
            mv "$f" "/tmp/awd_quarantine/$(basename $f).$(date +%s)" 2>/dev/null
        done
    fi

    # 4. 检查 /tmp 下的可疑 PHP
    TMP_PHP=$(find /tmp /var/tmp -name "*.php" -type f 2>/dev/null | grep -v "awd_")
    if [ -n "$TMP_PHP" ]; then
        echo "[$TS] [临时目录PHP]" >> $LOG
        echo "$TMP_PHP" >> $LOG
        rm -f $TMP_PHP
    fi

    # 5. 扫描隐藏后门文件 (.开头)
    HIDDEN=$(find /app -name ".*.php" -o -name ".*.phtml" 2>/dev/null | grep -v ".awd_security" | grep -v ".htaccess")
    if [ -n "$HIDDEN" ]; then
        echo "[$TS] [隐藏PHP文件]" >> $LOG
        echo "$HIDDEN" >> $LOG
    fi

    # 6. 更新基线
    echo "$CURRENT" > "$BASELINE"

    sleep 60
done
SCANEOF

# 2. 自动改密脚本 (每10分钟)
read -r -d '' PASS_SCRIPT << 'PASSEOF'
#!/bin/bash
# 自动改密 - 每10分钟
LOG="/tmp/awd_changepass.log"
echo "=== 改密启动 $(date) ===" >> $LOG

GEN_PASS() {
    cat /dev/urandom | tr -dc 'A-Za-z0-9#@$!%*' | head -c 16
}

while true; do
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 600  # 10 分钟

    NEW_DB=$(GEN_PASS)
    NEW_ADMIN=$(GEN_PASS)
    SALT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 6)

    # 获取当前数据库密码
    CUR_DB=$(grep "DB_PWD" /app/App/Common/Conf/db.php 2>/dev/null | grep -oP "'[^']+'" | tail -1 | tr -d "'")
    [ -z "$CUR_DB" ] && continue

    # 修改数据库密码
    mysql -ucms -p"$CUR_DB" -h127.0.0.1 -e "SET PASSWORD FOR 'cms'@'localhost' = PASSWORD('$NEW_DB'); SET PASSWORD FOR 'cms'@'%' = PASSWORD('$NEW_DB'); FLUSH PRIVILEGES;" 2>/dev/null
    if [ $? -eq 0 ]; then
        sed -i "s|'DB_PWD' => '.*'|'DB_PWD' => '$NEW_DB'|" /app/App/Common/Conf/db.php
        echo "[$TS] [+] DB密码已更新: $NEW_DB" >> $LOG
    else
        echo "[$TS] [-] DB密码修改失败" >> $LOG
        continue
    fi

    # 修改管理员密码
    HASH=$(php -r "echo md5(md5('$NEW_ADMIN').'$SALT');" 2>/dev/null)
    mysql -ucms -p"$NEW_DB" -h127.0.0.1 cms -e "UPDATE xy_admin SET password='$HASH', encrypt='$SALT' WHERE username='admin';" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[$TS] [+] 管理员密码已更新: $NEW_ADMIN (盐: $SALT)" >> $LOG
    fi

    # 修改 Cookie 密钥
    COOKIE=$(GEN_PASS)
    mysql -ucms -p"$NEW_DB" -h127.0.0.1 cms -e "UPDATE xy_config SET value='$COOKIE' WHERE name='CFG_COOKIE_ENCODE';" 2>/dev/null

    # 清理 session 强制重新登录
    rm -rf /tmp/sess_* /var/lib/php5/sess_* 2>/dev/null

    # 清理缓存
    cat > /app/.awd_security/_clean.php << 'CLN'
<?php
function rrmdir($d) { foreach(@glob($d."/*") as $i) { is_dir($i) ? rrmdir($i) : @unlink($i); } @rmdir($d); }
rrmdir("/app/App/Runtime");
@mkdir("/app/App/Runtime", 0777, true);
CLN
    wget -q -O /dev/null "http://127.0.0.1/.awd_security/_clean.php" 2>/dev/null
    rm -f /app/.awd_security/_clean.php

    echo "[$TS] === 轮换完成 ===" >> $LOG
done
PASSEOF

# ====================== 主控制逻辑 ======================
case "$ACTION" in
    start)
        echo "[+] 部署脚本到靶机..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "mkdir -p /tmp/awd_quarantine"

        # 上传扫描脚本
        echo "$SCAN_SCRIPT" | sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "cat > /tmp/awd_hidden_scan.sh && chmod +x /tmp/awd_hidden_scan.sh"

        # 上传改密脚本
        echo "$PASS_SCRIPT" | sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "cat > /tmp/awd_changepass.sh && chmod +x /tmp/awd_changepass.sh"

        # 启动后台进程
        echo "[+] 启动监控进程..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            # 停止旧的
            pkill -f awd_hidden_scan.sh 2>/dev/null
            pkill -f awd_changepass.sh 2>/dev/null
            sleep 1
            # 启动新的
            nohup bash /tmp/awd_hidden_scan.sh > /dev/null 2>&1 &
            echo \$! > /tmp/awd_scan.pid
            nohup bash /tmp/awd_changepass.sh > /dev/null 2>&1 &
            echo \$! > /tmp/awd_pass.pid
            sleep 1
            echo '扫描进程 PID:' \$(cat /tmp/awd_scan.pid)
            echo '改密进程 PID:' \$(cat /tmp/awd_pass.pid)
            ps aux | grep -E 'awd_hidden|awd_changepass' | grep -v grep
        "
        echo ""
        echo "[+] 部署完成!"
        echo "    - 后台扫描: 每60秒 (日志: /tmp/awd_hidden_scan.log)"
        echo "    - 自动改密: 每10分钟 (日志: /tmp/awd_changepass.log)"
        ;;

    stop)
        echo "[+] 停止靶机上的监控进程..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            pkill -f awd_hidden_scan.sh 2>/dev/null
            pkill -f awd_changepass.sh 2>/dev/null
            echo '已停止'
            ps aux | grep -E 'awd_hidden|awd_changepass' | grep -v grep || echo '无运行进程'
        "
        ;;

    status)
        echo "[+] 监控状态..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            echo '=== 进程状态 ==='
            ps aux | grep -E 'awd_hidden|awd_changepass' | grep -v grep || echo '无运行进程'
            echo ''
            echo '=== 扫描日志 (最后10行) ==='
            tail -10 /tmp/awd_hidden_scan.log 2>/dev/null || echo '无日志'
            echo ''
            echo '=== 改密日志 (最后10行) ==='
            tail -10 /tmp/awd_changepass.log 2>/dev/null || echo '无日志'
        "
        ;;

    scan)
        echo "[+] 立即扫描后台隐藏文件..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            echo '=== 隐藏文件 (.开头) ==='
            find /app -name '.*' -type f 2>/dev/null | grep -v '.awd_security' | grep -v '.git' | grep -v '.DS_Store'
            echo ''
            echo '=== 可疑文件名 ==='
            find /app -type f \( -name 'shell*.php' -o -name 'cmd*.php' -o -name 'test*.php' -o -name 'tmp*.php' -o -name '1.php' -o -name '0.php' -o -name 'x.php' -o -name 'c.php' -o -name '*.php.bak' -o -name '*.php.old' \) 2>/dev/null | grep -v Runtime
            echo ''
            echo '=== 上传目录 PHP 文件 ==='
            find /app/uploads /app/avatar /app/Data -name '*.php' -type f 2>/dev/null
            echo ''
            echo '=== /tmp 下的 PHP 文件 ==='
            find /tmp /var/tmp -name '*.php' -type f 2>/dev/null | grep -v awd_
            echo ''
            echo '=== 后台目录 (xyhai相关) ==='
            find /app -name '*xyhai*' -type f 2>/dev/null
            echo ''
            echo '=== .htaccess 文件 ==='
            find /app -name '.htaccess' -type f 2>/dev/null
            echo ''
            echo '=== .user.ini 文件 ==='
            find /app -name '.user.ini' -type f 2>/dev/null
            echo ''
            echo '=== 含木马特征的文件 ==='
            grep -rlE 'eval\s*\(\s*\$_(POST|GET|REQUEST)|(system|exec|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST)|assert\s*\(\s*\$_(POST|GET|REQUEST)' /app --include='*.php' 2>/dev/null | grep -v '.awd_security' | grep -v Runtime | head -10
        "
        ;;

    changepass)
        echo "[+] 立即修改所有密码..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            GEN_PASS() { cat /dev/urandom | tr -dc 'A-Za-z0-9#@\$!%*' | head -c 16; }
            NEW_DB=\$(GEN_PASS)
            NEW_ADMIN=\$(GEN_PASS)
            SALT=\$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 6)
            CUR_DB=\$(grep 'DB_PWD' /app/App/Common/Conf/db.php | grep -oP \"'[^']+'\" | tail -1 | tr -d \"'\")
            mysql -ucms -p\"\$CUR_DB\" -h127.0.0.1 -e \"SET PASSWORD FOR 'cms'@'localhost' = PASSWORD('\$NEW_DB'); SET PASSWORD FOR 'cms'@'%' = PASSWORD('\$NEW_DB'); FLUSH PRIVILEGES;\" 2>/dev/null
            sed -i \"s|'DB_PWD' => '.*'|'DB_PWD' => '\$NEW_DB'|\" /app/App/Common/Conf/db.php
            HASH=\$(php -r \"echo md5(md5('\$NEW_ADMIN').'\$SALT');\" 2>/dev/null)
            mysql -ucms -p\"\$NEW_DB\" -h127.0.0.1 cms -e \"UPDATE xy_admin SET password='\$HASH', encrypt='\$SALT' WHERE username='admin';\" 2>/dev/null
            COOKIE=\$(GEN_PASS)
            mysql -ucms -p\"\$NEW_DB\" -h127.0.0.1 cms -e \"UPDATE xy_config SET value='\$COOKIE' WHERE name='CFG_COOKIE_ENCODE';\" 2>/dev/null
            rm -rf /tmp/sess_* /var/lib/php5/sess_* 2>/dev/null
            echo '=== 新密码 ==='
            echo \"DB: \$NEW_DB\"
            echo \"Admin: \$NEW_ADMIN (盐: \$SALT)\"
            echo \"Cookie: \$COOKIE\"
            echo ''
            echo '=== 验证 ==='
            mysql -ucms -p\"\$NEW_DB\" -h127.0.0.1 cms -e 'SELECT 1;' 2>/dev/null && echo 'DB连接: OK' || echo 'DB连接: 失败'
        "
        ;;

    logs)
        echo "[+] 查看日志..."
        sshpass -p "$SSH_PASS" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$TARGET_HOST "
            echo '=== 扫描日志 ==='
            tail -30 /tmp/awd_hidden_scan.log 2>/dev/null
            echo ''
            echo '=== 改密日志 ==='
            tail -20 /tmp/awd_changepass.log 2>/dev/null
        "
        ;;

    *)
        echo "用法: bash $0 {start|stop|status|scan|changepass|logs}"
        echo ""
        echo "  start      - 部署并启动监控+改密"
        echo "  stop       - 停止监控"
        echo "  status     - 查看状态"
        echo "  scan       - 立即扫描隐藏文件"
        echo "  changepass - 立即修改密码"
        echo "  logs       - 查看日志"
        ;;
esac
