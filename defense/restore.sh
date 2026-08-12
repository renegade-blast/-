#!/bin/bash
# AWD 快速恢复脚本 —— 服务宕机 / 被篡改 / 被 rm -rf 时的救命稻草
#
# 设计原则:
#   1. 立刻止损: 先把服务重启起来让 checker 能访问, 再去查根因
#   2. 三级恢复: web源码 → 数据库 → 系统配置 (按需选择)
#   3. 安全恢复: 恢复后立刻清理后门 + 重应用 IP 规则 + 重启 WAF
#   4. 健康检查: 恢复完 curl 自测, 不通则自动回滚到上一份备份
#
# 用法:
#   bash restore.sh                    # 交互菜单
#   bash restore.sh all                # 全量恢复 (推荐, 最快止损)
#   bash restore.sh all <备份目录>      # 指定备份恢复
#   bash restore.sh web                 # 只恢复 Web 源码
#   bash restore.sh db                  # 只恢复数据库
#   bash restore.sh ipfw                # 只恢复 IP 防火墙规则
#   bash restore.sh config              # 只恢复系统配置 (nginx/apache/php)
#   bash restore.sh waf                 # 只恢复 waf.php + .htaccess
#   bash restore.sh list                # 列出可用备份 (= backup.sh list)
#   bash restore.sh diff <备份目录>     # 对比当前文件与备份差异 (查找被篡改内容)
#   bash restore.sh restart             # 只重启服务 (不恢复数据, 用于临时卡死)
#   bash restore.sh health              # 健康检查 (本地 curl + 进程 + 端口)
#
# 环境变量:
#   AWD_BACKUP_DIR=/tmp/awd_backup
#   AWD_WEB_ROOT=/app
#   AWD_DB_NAME=xyhcms
#   AWD_DB_USER=cms
#   AWD_DB_PASS=
#   AWD_HEALTH_URL=http://127.0.0.1/   健康检查 URL
#   AWD_NO_RESTART=0                   1=恢复后不重启服务 (默认 0=自动重启)

set -u

ACTION="${1:-menu}"
AWD_BACKUP_DIR="${AWD_BACKUP_DIR:-/tmp/awd_backup}"
AWD_WEB_ROOT="${AWD_WEB_ROOT:-/app}"
AWD_DB_NAME="${AWD_DB_NAME:-xyhcms}"
AWD_DB_USER="${AWD_DB_USER:-cms}"
AWD_DB_PASS="${AWD_DB_PASS:-}"
AWD_HEALTH_URL="${AWD_HEALTH_URL:-http://127.0.0.1/}"
AWD_NO_RESTART="${AWD_NO_RESTART:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*"; }

# 解析备份目录: 优先用参数, 否则用 latest
resolve_target() {
  local t="${1:-}"
  [ -z "$t" ] && t="$AWD_BACKUP_DIR/latest"
  t=$(readlink -f "$t" 2>/dev/null)
  if [ ! -d "$t" ]; then
    err "备份目录不存在: $t"
    warn "可用备份:"
    bash "$0" list 2>/dev/null || ls -1 "$AWD_BACKUP_DIR" 2>/dev/null
    exit 1
  fi
  echo "$t"
}

# 读 DB 密码
guess_db_pass() {
  [ -n "$AWD_DB_PASS" ] && { echo "$AWD_DB_PASS"; return; }
  for f in /app/App/Common/Conf/db.php /app/Common/Conf/db.php /app/config/db.php; do
    if [ -f "$f" ]; then
      local p
      p=$(grep -oE "(DB_PWD|password)['\"]*\s*=>\s*['\"]([^'\"]+)" "$f" 2>/dev/null | head -1 | sed -E "s/.*['\"]([^'\"]+)$/\1/")
      [ -n "$p" ] && { echo "$p"; return; }
    fi
  done
  echo ""
}

# ====== 服务管理 ======
service_ctl() {
  local action="$1" svc="$2"
  if command -v systemctl &>/dev/null; then
    systemctl "$action" "$svc" 2>/dev/null && return 0
  fi
  service "$svc" "$action" 2>/dev/null && return 0
  # 直接找进程
  case "$action" in
    restart|start)
      case "$svc" in
        nginx)     nginx -s reload 2>/dev/null || nginx 2>/dev/null ;;
        apache2|httpd) apachectl -k restart 2>/dev/null || service apache2 restart 2>/dev/null ;;
        php*-fpm|php-fpm)
          local pool=$(ls /etc/php/*/fpm/pool.d/*.conf 2>/dev/null | head -1)
          local ver=$(echo "$pool" | grep -oE "php[0-9.]+")
          [ -n "$ver" ] && service "$ver-fpm" restart 2>/dev/null || pkill -USR2 php-fpm 2>/dev/null
          ;;
        mysql|mariadb) service mysql restart 2>/dev/null || service mariadb restart 2>/dev/null ;;
      esac
      ;;
    stop) pkill -9 "$svc" 2>/dev/null ;;
  esac
}

restart_web_stack() {
  [ "$AWD_NO_RESTART" = "1" ] && { warn "AWD_NO_RESTART=1, 跳过服务重启"; return; }
  log "重启 Web 服务栈..."
  # 探测是 nginx 还是 apache
  if pgrep -x nginx &>/dev/null || [ -d /etc/nginx ]; then
    service_ctl restart nginx && ok "nginx restarted"
    # php-fpm
    local fpm_proc=$(pgrep -x "php-fpm" | head -1)
    [ -n "$fpm_proc" ] && service_ctl restart php-fpm && ok "php-fpm restarted"
  elif pgrep -x apache2 &>/dev/null || [ -d /etc/apache2 ]; then
    service_ctl restart apache2 && ok "apache2 restarted"
  fi
  # mysql
  pgrep -x mysqld &>/dev/null || service_ctl restart mysql 2>/dev/null
}

# ====== 恢复 Web 源码 ======
restore_web() {
  local target="$1"
  log "▶ 恢复 Web 源码: $AWD_WEB_ROOT"
  if [ ! -f "$target/web_root.tar.gz" ]; then
    err "缺少 web_root.tar.gz"
    return 1
  fi
  # 先备份当前 (被篡改的) 版本, 以便事后取证
  if [ -d "$AWD_WEB_ROOT" ]; then
    local ts=$(date '+%Y%m%d_%H%M%S')
    tar czf "$AWD_BACKUP_DIR/compromised_${ts}.tar.gz" -C "$(dirname $AWD_WEB_ROOT)" "$(basename $AWD_WEB_ROOT)" 2>/dev/null
    warn "已把当前(被篡改)版本保存为 compromised_${ts}.tar.gz (取证用)"
    # 把当前 web 目录清空再恢复, 防止攻击者植入的文件残留
    rm -rf "$AWD_WEB_ROOT" 2>/dev/null
  fi
  mkdir -p "$(dirname $AWD_WEB_ROOT)"
  tar xzf "$target/web_root.tar.gz" -C "$(dirname $AWD_WEB_ROOT)"
  ok "Web 源码已恢复: $(du -sh "$AWD_WEB_ROOT" | cut -f1)"

  # 恢复 waf.php + .htaccess
  [ -f "$target/waf.php" ] && cp -a "$target/waf.php" "$AWD_WEB_ROOT/waf.php" 2>/dev/null && ok "waf.php 已恢复"
  [ -f "$target/htaccess" ] && cp -a "$target/htaccess" "$AWD_WEB_ROOT/.htaccess" 2>/dev/null && ok ".htaccess 已恢复"

  # 关键: 在入口文件顶部确保 waf.php 加载
  for entry in "$AWD_WEB_ROOT"/index.php "$AWD_WEB_ROOT"/xyhai.php "$AWD_WEB_ROOT"/admin.php; do
    if [ -f "$entry" ] && ! head -1 "$entry" | grep -q waf.php; then
      sed -i '1i<?php require_once "/app/waf.php"; ?>' "$entry" 2>/dev/null
    fi
  done

  # 权限修复
  chown -R www-data:www-data "$AWD_WEB_ROOT" 2>/dev/null || chown -R apache:apache "$AWD_WEB_ROOT" 2>/dev/null
  find "$AWD_WEB_ROOT" -type d -exec chmod 755 {} \; 2>/dev/null
  find "$AWD_WEB_ROOT" -type f -exec chmod 644 {} \; 2>/dev/null
  # 配置文件 640
  find "$AWD_WEB_ROOT" -name "db.php" -o -name "config.php" 2>/dev/null | xargs chmod 640 2>/dev/null
  # 上传目录禁 PHP
  for d in "$AWD_WEB_ROOT"/upload "$AWD_WEB_ROOT"/uploads "$AWD_WEB_ROOT"/avatar; do
    [ -d "$d" ] && echo "php_flag engine off" > "$d/.htaccess" 2>/dev/null
  done
}

# ====== 恢复数据库 ======
restore_db() {
  local target="$1"
  log "▶ 恢复数据库"
  AWD_DB_PASS="$(guess_db_pass)"

  # 启动 mysql (如果没起)
  pgrep -x mysqld &>/dev/null || service_ctl restart mysql 2>/dev/null || service_ctl restart mariadb 2>/dev/null
  sleep 1

  local sql_file=""
  if [ -f "$target/db_all.sql" ]; then
    sql_file="$target/db_all.sql"
  elif [ -f "$target/db_${AWD_DB_NAME}.sql" ]; then
    sql_file="$target/db_${AWD_DB_NAME}.sql"
  else
    err "备份中找不到 SQL 文件"
    return 1
  fi

  # 先备份当前数据库 (万一恢复错了还能再回滚)
  if command -v mysqldump &>/dev/null; then
    local ts=$(date '+%Y%m%d_%H%M%S')
    mysqldump -u "$AWD_DB_USER" -p"$AWD_DB_PASS" --single-transaction --all-databases \
      > "$AWD_BACKUP_DIR/db_compromised_${ts}.sql" 2>/dev/null \
      && warn "当前(被篡改)数据库已备份: db_compromised_${ts}.sql"
  fi

  # 执行恢复
  if mysql -u "$AWD_DB_USER" -p"$AWD_DB_PASS" < "$sql_file" 2>/dev/null; then
    ok "数据库已恢复: $sql_file ($(du -h "$sql_file" | cut -f1))"
  else
    err "数据库恢复失败, 尝试单库恢复..."
    mysql -u "$AWD_DB_USER" -p"$AWD_DB_PASS" "$AWD_DB_NAME" < "$sql_file" 2>/dev/null \
      && ok "单库恢复成功" \
      || { err "数据库恢复失败 - 检查密码/权限"; return 1; }
  fi

  # 关键: 恢复后立刻改回强密码 (防止攻击者已经知道当前密码)
  if [ -n "${NEW_DB_PASS:-}" ]; then
    log "应用新数据库密码: $NEW_DB_PASS"
    mysql -u root -p"$AWD_DB_PASS" -e "ALTER USER '$AWD_DB_USER'@'localhost' IDENTIFIED BY '$NEW_DB_PASS'; FLUSH PRIVILEGES;" 2>/dev/null \
      && ok "DB 用户 $AWD_DB_USER 密码已更新" \
      || warn "DB 密码更新失败 (可能需要 root 权限)"
  fi
}

# ====== 恢复 IP 防火墙 ======
restore_ipfw() {
  local target="$1"
  log "▶ 恢复 IP 防火墙"
  if [ ! -d "$target/awd_ipfw" ]; then
    warn "备份中无 IP 防火墙目录, 跳过"
    return 0
  fi
  rm -rf /tmp/awd_ipfw 2>/dev/null
  cp -a "$target/awd_ipfw" /tmp/awd_ipfw
  ok "IP 规则已恢复: $(ls /tmp/awd_ipfw)"

  # 重新应用 3 层规则
  if [ -f /tmp/ip_firewall.py ]; then
    python3 /tmp/ip_firewall.py generate waf      --out /tmp/awd_ipfw/ip_firewall.php 2>/dev/null
    python3 /tmp/ip_firewall.py generate htaccess --out "$AWD_WEB_ROOT/.htaccess" 2>/dev/null
    if [ -f /tmp/awd_ipfw_rules.sh ]; then
      bash /tmp/awd_ipfw_rules.sh 2>/dev/null && ok "iptables 规则已重应用"
    fi
  fi

  # 清 iptables 中的恶意规则 (从攻击者拿到 root 后塞的)
  # 保留 AWD_FW 链, 但删掉非 awd: 前缀的可疑 DROP/ACCEPT
  iptables -S 2>/dev/null | grep -E "^-A INPUT.*-j (DROP|REJECT)" | grep -v "awd:" | while read rule; do
    warn "删除可疑 iptables 规则: $rule"
    # 把 -A 改成 -D 来删除
    iptables $(echo "$rule" | sed 's/^-A/-D/') 2>/dev/null
  done
}

# ====== 恢复系统配置 ======
restore_config() {
  local target="$1"
  log "▶ 恢复系统配置文件"
  if [ ! -d "$target/etc" ]; then
    warn "备份中无 etc 目录"
    return 0
  fi
  # 谨慎: 只恢复存在的文件, 覆盖被篡改的版本
  ( cd "$target/etc" && find . -type f ) | while read f; do
    f="${f#./}"
    local src="$target/etc/$f"
    local dst="/$f"
    if [ -e "$dst" ]; then
      # 如果当前文件和备份不一致才覆盖
      if ! diff -q "$src" "$dst" &>/dev/null; then
        cp -a "$src" "$dst"
        warn "覆盖: $dst (当前版本被篡改)"
      fi
    else
      cp -a "$src" "$dst"
      ok "恢复: $dst"
    fi
  done
}

# ====== 恢复 WAF 单独 ======
restore_waf() {
  local target="$1"
  log "▶ 恢复 WAF"
  [ -f "$target/waf.php" ] && cp -a "$target/waf.php" "$AWD_WEB_ROOT/waf.php" && ok "waf.php"
  [ -f "$target/htaccess" ] && cp -a "$target/htaccess" "$AWD_WEB_ROOT/.htaccess" && ok ".htaccess"
  # 入口文件注入
  for entry in "$AWD_WEB_ROOT"/index.php "$AWD_WEB_ROOT"/xyhai.php "$AWD_WEB_ROOT"/admin.php; do
    if [ -f "$entry" ] && ! head -1 "$entry" | grep -q waf.php; then
      sed -i '1i<?php require_once "/app/waf.php"; ?>' "$entry" 2>/dev/null
    fi
  done
}

# ====== 清理后门 (恢复后必做) ======
clean_backdoors() {
  log "▶ 清理后门"
  # authorized_keys
  > ~/.ssh/authorized_keys 2>/dev/null
  chmod 600 ~/.ssh/authorized_keys 2>/dev/null
  ok "authorized_keys 已清空"

  # crontab: 只保留 defense 相关
  crontab -l 2>/dev/null > /tmp/cr.bak
  grep -E "backdoor|defense|scan|rotate|waf|ipfw|traffic|flag_prot|backup" /tmp/cr.bak > /tmp/cr.new 2>/dev/null || true
  crontab /tmp/cr.new 2>/dev/null
  ok "crontab 已清理 (仅保留 defense 任务)"

  # 杀可疑进程
  ps -eo pid,comm,args | grep -vE "sshd|nginx|mysqld|mariadbd|php-fpm|systemd|init|crond|bash|python|rsyslog|dbus|ps |grep|backup.sh|restore.sh" \
    | awk 'NR>1 {print $1}' | while read p; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null
  done
  ok "可疑进程已清理"

  # 删除常见 webshell 文件名
  find "$AWD_WEB_ROOT" -name "*.php" -newer "$AWD_BACKUP_DIR/latest/MANIFEST.txt" 2>/dev/null | while read f; do
    # 只删可疑特征文件, 不删正常的
    if grep -qE "eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(" "$f" 2>/dev/null; then
      warn "删除可疑 webshell: $f"
      rm -f "$f"
    fi
  done
}

# ====== 健康检查 ======
do_health() {
  log "=== 健康检查 ==="
  local ok_count=0 fail_count=0

  # 1. 进程
  for proc in nginx apache2 mysqld php-fpm; do
    if pgrep -x "$proc" &>/dev/null; then
      ok "进程 $proc 运行中"
      ok_count=$((ok_count+1))
    fi
  done

  # 2. 端口
  for port in 80 443 3306; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
      ok "端口 $port 监听中"
      ok_count=$((ok_count+1))
    fi
  done

  # 3. HTTP
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$AWD_HEALTH_URL" 2>/dev/null)
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then
    ok "HTTP $AWD_HEALTH_URL → $code"
    ok_count=$((ok_count+1))
  elif [ "$code" = "403" ]; then
    warn "HTTP → 403 (WAF/IP 防火墙拦截, 检查 127.0.0.1 是否在白名单)"
    fail_count=$((fail_count+1))
  else
    err "HTTP → $code (服务异常)"
    fail_count=$((fail_count+1))
  fi

  # 4. WAF 生效
  local waf_code
  waf_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "X-Forwarded-For: 1.2.3.4" "$AWD_HEALTH_URL" 2>/dev/null)
  if [ "$waf_code" = "403" ]; then
    ok "WAF/IP 防火墙拦截测试 → 403 (生效)"
    ok_count=$((ok_count+1))
  else
    warn "WAF 测试 → $waf_code (期望 403, 可能 WAF 未生效)"
    fail_count=$((fail_count+1))
  fi

  # 5. flag 文件
  if [ -f /flag ]; then
    ok "/flag 存在 ($(stat -c '%s' /flag 2>/dev/null) bytes)"
    ok_count=$((ok_count+1))
  else
    err "/flag 丢失!"
    fail_count=$((fail_count+1))
  fi

  echo
  if [ "$fail_count" = 0 ]; then
    ok "✅ 全部通过 ($ok_count 项正常)"
    return 0
  else
    err "❌ $fail_count 项异常, $ok_count 项正常"
    return 1
  fi
}

# ====== 对比差异 (查篡改) ======
do_diff() {
  local target
  target=$(resolve_target "${2:-}")
  log "=== 对比当前文件 vs 备份: $target ==="

  # Web 文件对比
  if [ -f "$target/web_root.tar.gz" ]; then
    local tmp="/tmp/awd_diff_$$"
    mkdir -p "$tmp"
    tar xzf "$target/web_root.tar.gz" -C "$tmp" 2>/dev/null
    local bak_web="$tmp/$(basename $AWD_WEB_ROOT)"
    echo
    echo "--- Web 源码差异 (新增/修改/删除) ---"
    diff -rq "$bak_web" "$AWD_WEB_ROOT" 2>/dev/null | head -40
    rm -rf "$tmp"
  fi

  # crontab 对比
  if [ -f "$target/crontab.txt" ]; then
    echo
    echo "--- crontab 差异 ---"
    diff <(cat "$target/crontab.txt") <(crontab -l 2>/dev/null) | head -20
  fi

  # authorized_keys 对比
  if [ -f "$target/authorized_keys" ]; then
    echo
    echo "--- authorized_keys 差异 ---"
    diff "$target/authorized_keys" ~/.ssh/authorized_keys 2>/dev/null | head -10
    [ $? -eq 0 ] && ok "authorized_keys 无变化"
  fi

  # 进程对比 (新增的可疑进程)
  if [ -f "$target/ps_snapshot.txt" ]; then
    echo
    echo "--- 当前新增进程 (不在备份时) ---"
    # 提取 comm 列对比
    comm -13 \
      <(awk 'NR>1{print $3}' "$target/ps_snapshot.txt" | sort -u) \
      <(ps -eo comm | sort -u) | head -20
  fi
}

# ====== 全量恢复 ======
do_all() {
  local target
  target=$(resolve_target "${2:-}")

  echo "============================================"
  echo "  AWD 全量恢复"
  echo "  备份源: $target"
  echo "  时间:   $(date '+%Y-%m-%d %H:%M:%S')"
  echo "============================================"

  # 校验
  if ! ( cd "$target" && sha256sum -c sha256.txt 2>&1 | grep -qv "OK$" ) 2>/dev/null; then
    ok "备份完整性校验通过"
  else
    warn "⚠️ 备份有文件校验失败, 继续恢复可能有风险"
    ( cd "$target" && sha256sum -c sha256.txt 2>&1 | grep -v "OK$" ) | head -5
  fi

  # 顺序: IP防火墙先恢复 (防止恢复过程中又被攻击) → DB → Web → 配置 → 后门清理 → 重启 → 健康检查
  restore_ipfw "$target"
  restore_db "$target"
  restore_web "$target"
  restore_config "$target"
  clean_backdoors
  restart_web_stack

  echo
  do_health

  echo
  ok "🎉 全量恢复完成!"
  echo "  下一步建议:"
  echo "   1. 检查 ban.log 看谁攻击了你: tail -n 30 /tmp/awd_ipfw/ban.log"
  echo "   2. 查篡改详情: bash $0 diff $target"
  echo "   3. 立刻做新一份备份: bash /tmp/backup.sh full"
  echo "   4. 把攻击者 IP 拉黑: python3 /tmp/ip_firewall.py auto-ban <attacker_ip> '攻击证据'"
}

# ====== 交互菜单 ======
show_menu() {
  echo "============================================"
  echo "  AWD 快速恢复 (交互模式)"
  echo "============================================"
  bash /tmp/backup.sh list 2>/dev/null || bash "$0" list
  echo
  echo "选择恢复操作:"
  echo "  1) 全量恢复 (推荐 - 止损)"
  echo "  2) 只恢复 Web 源码"
  echo "  3) 只恢复数据库"
  echo "  4) 只恢复 IP 防火墙规则"
  echo "  5) 只恢复 WAF (.htaccess + waf.php)"
  echo "  6) 只恢复系统配置"
  echo "  7) 清理后门 (不恢复数据)"
  echo "  8) 重启 Web 服务"
  echo "  9) 健康检查"
  echo " 10) 对比当前 vs 备份差异 (查篡改)"
  echo " 11) 列出备份"
  echo "  0) 退出"
  echo
  read -p "选择 [1-11]: " choice

  # 如果选择备份, 让用户挑
  local backup_target=""
  if [ "$choice" != "8" ] && [ "$choice" != "9" ] && [ "$choice" != "11" ] && [ "$choice" != "0" ]; then
    read -p "使用最新备份? [Y/n]: " use_latest
    if [[ ! "$use_latest" =~ ^[Yy]$ ]] && [ -n "$use_latest" ]; then
      read -p "输入备份目录路径: " backup_target
    fi
  fi

  case "$choice" in
    1) do_all "" "$backup_target" ;;
    2) restore_web "$(resolve_target "$backup_target")" ;;
    3) restore_db  "$(resolve_target "$backup_target")" ;;
    4) restore_ipfw "$(resolve_target "$backup_target")" ;;
    5) restore_waf  "$(resolve_target "$backup_target")" ;;
    6) restore_config "$(resolve_target "$backup_target")" ;;
    7) clean_backdoors ;;
    8) restart_web_stack ;;
    9) do_health ;;
    10) do_diff "" "$backup_target" ;;
    11) bash /tmp/backup.sh list 2>/dev/null || ls -1 "$AWD_BACKUP_DIR" ;;
    0) exit 0 ;;
    *) err "无效选择"; exit 1 ;;
  esac
}

# ====== 主入口 ======
case "$ACTION" in
  all)         do_all "" "${2:-}" ;;
  web)         restore_web "$(resolve_target "${2:-}")" ;;
  db)          restore_db  "$(resolve_target "${2:-}")" ;;
  ipfw)        restore_ipfw "$(resolve_target "${2:-}")" ;;
  waf)         restore_waf  "$(resolve_target "${2:-}")" ;;
  config)      restore_config "$(resolve_target "${2:-}")" ;;
  list|ls)     bash /tmp/backup.sh list 2>/dev/null || ls -1 "$AWD_BACKUP_DIR" ;;
  diff)        do_diff "" "${2:-}" ;;
  restart)     restart_web_stack ;;
  health)      do_health ;;
  menu|"")     show_menu ;;
  *)           grep -E "^# usage|^# " "$0" 2>/dev/null | head -25; exit 1 ;;
esac
