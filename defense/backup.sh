#!/bin/bash
# AWD 数据备份脚本 —— 完整快照 + 增量快照
#
# 备份内容:
#   1. Web 源码  (/app, /var/www 等)
#   2. 数据库    (mysqldump 全库 + 单库分离, 便于精准恢复)
#   3. 配置文件  (nginx/apache/php/mysql 配置)
#   4. IP 防火墙规则 (/tmp/awd_ipfw)
#   5. crontab / SSH authorized_keys (基线对照用)
#   6. 自定义 WAF / 防御脚本 (/tmp/awd_*.sh / /app/waf.php)
#
# 用法:
#   bash backup.sh full                # 完整备份 (比赛开打前/拿到靶机后立刻做)
#   bash backup.sh inc                 # 增量备份 (crontab 每 5 分钟)
#   bash backup.sh list                # 列出所有备份
#   bash backup.sh latest              # 打印最近一次备份路径
#   bash backup.sh verify <备份目录>   # 校验完整性
#   bash backup.sh purge 10            # 只保留最新 10 份
#
# 环境变量:
#   AWD_BACKUP_DIR=/tmp/awd_backup       备份根目录
#   AWD_WEB_ROOT=/app                    Web 根目录
#   AWD_DB_NAME=xyhcms                   数据库名 (多个用逗号分隔, all=全库)
#   AWD_DB_USER=cms                      数据库用户
#   AWD_DB_PASS=                         数据库密码 (留空则尝试常见配置文件读取)

set -u

ACTION="${1:-list}"
AWD_BACKUP_DIR="${AWD_BACKUP_DIR:-/tmp/awd_backup}"
AWD_WEB_ROOT="${AWD_WEB_ROOT:-/app}"
AWD_DB_NAME="${AWD_DB_NAME:-xyhcms}"
AWD_DB_USER="${AWD_DB_USER:-cms}"
AWD_DB_PASS="${AWD_DB_PASS:-}"

mkdir -p "$AWD_BACKUP_DIR"

# 从配置文件读 DB 密码 (如果环境变量没传)
guess_db_pass() {
  [ -n "$AWD_DB_PASS" ] && { echo "$AWD_DB_PASS"; return; }
  for f in /app/App/Common/Conf/db.php /app/Common/Conf/db.php /app/config/db.php /app/config/database.php /app/.env; do
    if [ -f "$f" ]; then
      # 兼容 PHP 数组 / .env 两种格式
      p=$(grep -oE "(DB_PWD|DB_PASSWORD|password|DB_PASS)['\"]*\s*=>\s*['\"]([^'\"]+)" "$f" 2>/dev/null | head -1 | sed -E "s/.*['\"]([^'\"]+)$/\1/")
      [ -n "$p" ] && { echo "$p"; return; }
      p=$(grep -E "^DB_PASSWORD=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
      [ -n "$p" ] && { echo "$p"; return; }
    fi
  done
  echo ""
}

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# ======= 备份执行 =======
do_backup() {
  local mode="$1"  # full | inc
  local ts subdir
  ts=$(date '+%Y%m%d_%H%M%S')
  subdir="${AWD_BACKUP_DIR}/${ts}_${mode}"
  mkdir -p "$subdir"

  log "▶ 开始 ${mode} 备份 → $subdir"

  # ---- 1. Web 源码 ----
  log "  [1/6] Web 源码 ($AWD_WEB_ROOT)"
  if [ -d "$AWD_WEB_ROOT" ]; then
    if [ "$mode" = "full" ]; then
      tar czf "$subdir/web_root.tar.gz" \
        --exclude="$AWD_WEB_ROOT/Runtime/Cache" \
        --exclude="$AWD_WEB_ROOT/Runtime/Logs" \
        --exclude="$AWD_WEB_ROOT/Runtime/Temp" \
        --exclude="$AWD_WEB_ROOT/Public/Upload" \
        -C "$(dirname $AWD_WEB_ROOT)" "$(basename $AWD_WEB_ROOT)" 2>/dev/null
    else
      # 增量: 只打包最近 10 分钟变更的文件
      find "$AWD_WEB_ROOT" -type f -mmin -10 \
        ! -path "*/Runtime/Cache/*" \
        ! -path "*/Runtime/Logs/*" \
        ! -path "*/Runtime/Temp/*" \
        ! -path "*/Public/Upload/*" \
        > "$subdir/inc_files.txt" 2>/dev/null
      if [ -s "$subdir/inc_files.txt" ]; then
        tar czf "$subdir/web_inc.tar.gz" -T "$subdir/inc_files.txt" 2>/dev/null
      else
        echo "(无变更)" > "$subdir/web_inc.tar.gz.skip"
      fi
    fi
  else
    echo "(目录不存在: $AWD_WEB_ROOT)" > "$subdir/web_root.skip"
  fi

  # ---- 2. 数据库 ----
  log "  [2/6] 数据库"
  if command -v mysqldump &>/dev/null; then
    AWD_DB_PASS="$(guess_db_pass)"
    # 全库 (结构+数据+事件+触发器+例程)
    if mysqldump -u "$AWD_DB_USER" -p"$AWD_DB_PASS" \
        --single-transaction --quick --routines --triggers --events \
        --all-databases > "$subdir/db_all.sql" 2>/dev/null; then
      log "    ✓ db_all.sql ($(du -h "$subdir/db_all.sql" | cut -f1))"
    else
      # 全库失败 → 退而求其次，备单个目标库
      mysqldump -u "$AWD_DB_USER" -p"$AWD_DB_PASS" \
          --single-transaction --quick --routines --triggers \
          "$AWD_DB_NAME" > "$subdir/db_${AWD_DB_NAME}.sql" 2>/dev/null \
        && log "    ✓ db_${AWD_DB_NAME}.sql" \
        || echo "(mysqldump 失败 - 检查用户/密码)" > "$subdir/db.skip"
    fi
    # 同时备一份纯结构 (用于对比篡改)
    mysqldump -u "$AWD_DB_USER" -p"$AWD_DB_PASS" --no-data \
        --single-transaction "$AWD_DB_NAME" > "$subdir/db_${AWD_DB_NAME}_schema.sql" 2>/dev/null
  else
    echo "(mysqldump 未安装)" > "$subdir/db.skip"
  fi

  # ---- 3. 系统配置文件 ----
  log "  [3/6] 系统配置"
  mkdir -p "$subdir/etc"
  for f in /etc/nginx/nginx.conf /etc/nginx/sites-enabled \
           /etc/apache2/apache2.conf /etc/apache2/sites-enabled \
           /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini \
           /etc/mysql/my.cnf /etc/my.cnf /etc/redis/redis.conf \
           /etc/ssh/sshd_config /etc/crontab; do
    [ -e "$f" ] && cp -a "$f" "$subdir/etc/" 2>/dev/null
  done
  # php-fpm pool 配置
  find /etc/php -name "*.conf" -path "*/fpm/*" -exec cp -a {} "$subdir/etc/" \; 2>/dev/null

  # ---- 4. IP 防火墙规则 + WAF ----
  log "  [4/6] IP 防火墙 + WAF"
  if [ -d /tmp/awd_ipfw ]; then
    cp -a /tmp/awd_ipfw "$subdir/awd_ipfw" 2>/dev/null
  fi
  [ -f /app/waf.php ] && cp -a /app/waf.php "$subdir/waf.php"
  [ -f /app/.htaccess ] && cp -a /app/.htaccess "$subdir/htaccess"
  # iptables 规则快照
  iptables -L -n -v > "$subdir/iptables_rules.txt" 2>/dev/null
  iptables -S > "$subdir/iptables_save.txt" 2>/dev/null

  # ---- 5. crontab + authorized_keys (基线对照) ----
  log "  [5/6] crontab + SSH keys"
  crontab -l > "$subdir/crontab.txt" 2>/dev/null || echo "(no crontab)" > "$subdir/crontab.txt"
  cp -a ~/.ssh/authorized_keys "$subdir/authorized_keys" 2>/dev/null || echo "(无 authorized_keys)" > "$subdir/authorized_keys.skip"
  # 当前进程快照 (用于事后对比异常进程)
  ps -eo pid,user,comm,args > "$subdir/ps_snapshot.txt" 2>/dev/null
  # 监听端口快照
  ss -tlnp > "$subdir/listen_ports.txt" 2>/dev/null

  # ---- 6. 备份清单 + 校验文件 ----
  log "  [6/6] 生成 manifest"
  cat > "$subdir/MANIFEST.txt" <<EOF
backup_mode   = $mode
backup_time   = $(date '+%Y-%m-%d %H:%M:%S')
backup_host   = $(hostname)
backup_user   = $(whoami)
web_root      = $AWD_WEB_ROOT
db_name       = $AWD_DB_NAME
db_user       = $AWD_DB_USER
files_count   = $(find "$subdir" -type f | wc -l)
total_size    = $(du -sh "$subdir" | cut -f1)
EOF
  # 全文件 sha256 (恢复前可校验)
  ( cd "$subdir" && find . -type f ! -name sha256.txt -exec sha256sum {} \; > sha256.txt )

  # 写一个 latest 软链接，方便恢复时直接拿
  ln -sfn "$subdir" "$AWD_BACKUP_DIR/latest"

  log "✅ 备份完成: $subdir  ($(du -sh "$subdir" | cut -f1))"
  echo "$subdir"
}

# ======= 列出所有备份 =======
do_list() {
  echo "=== AWD 备份列表 ==="
  echo "存储目录: $AWD_BACKUP_DIR"
  echo "总占用:   $(du -sh "$AWD_BACKUP_DIR" 2>/dev/null | cut -f1)"
  echo
  printf "%-22s %-6s %-10s %-10s %s\n" "TIME" "MODE" "SIZE" "FILES" "PATH"
  echo "------------------------------------------------------------------------"
  for d in "$AWD_BACKUP_DIR"/*_*; do
    [ -d "$d" ] || continue
    local name ts mode size files
    name=$(basename "$d")
    ts="${name%%_*}"
    mode="${name##*_}"
    size=$(du -sh "$d" 2>/dev/null | cut -f1)
    files=$(find "$d" -type f | wc -l)
    # 友好时间
    local friendly
    friendly=$(echo "$ts" | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})_([0-9]{2})([0-9]{2})([0-9]{2})/\1-\2-\3 \4:\5:\6/')
    printf "%-22s %-6s %-10s %-10s %s\n" "$friendly" "$mode" "$size" "$files" "$d"
  done | sort
  echo
  if [ -L "$AWD_BACKUP_DIR/latest" ]; then
    echo "📌 latest → $(readlink -f "$AWD_BACKUP_DIR/latest")"
  fi
}

# ======= 校验备份完整性 =======
do_verify() {
  local target="$1"
  if [ -z "$target" ]; then
    target="$AWD_BACKUP_DIR/latest"
  fi
  target=$(readlink -f "$target" 2>/dev/null)
  if [ ! -d "$target" ]; then
    echo "[!] 备份目录不存在: $target"
    return 1
  fi
  echo "=== 校验备份: $target ==="
  if [ ! -f "$target/sha256.txt" ]; then
    echo "[!] 缺少 sha256.txt, 无法校验"
    return 1
  fi
  echo "manifest:"
  cat "$target/MANIFEST.txt" 2>/dev/null
  echo
  echo "sha256 校验:"
  ( cd "$target" && sha256sum -c sha256.txt 2>&1 | tail -20 )
  echo
  if ( cd "$target" && sha256sum -c sha256.txt 2>&1 | grep -qv "OK$" ); then
    echo "❌ 校验失败: 有文件被篡改或丢失"
    return 1
  fi
  echo "✅ 所有文件校验通过"
}

# ======= 清理旧备份 =======
do_purge() {
  local keep="${1:-10}"
  echo "保留最新 $keep 份，删除其余..."
  local deleted=0
  ls -1dt "$AWD_BACKUP_DIR"/*_* 2>/dev/null | tail -n +$((keep+1)) | while read d; do
    [ -d "$d" ] || continue
    echo "  删除: $(basename "$d")"
    rm -rf "$d"
    deleted=$((deleted+1))
  done
  echo "完成"
}

# ======= 主入口 =======
case "$ACTION" in
  full)
    do_backup full
    ;;
  inc|incremental)
    do_backup inc
    ;;
  list|ls)
    do_list
    ;;
  latest)
    readlink -f "$AWD_BACKUP_DIR/latest" 2>/dev/null && \
      cat "$AWD_BACKUP_DIR/latest/MANIFEST.txt" 2>/dev/null
    ;;
  verify)
    do_verify "${2:-}"
    ;;
  purge|clean)
    do_purge "${2:-10}"
    ;;
  *)
    cat <<EOF
用法:
  $0 full                  完整备份 (拿到靶机第一件事)
  $0 inc                   增量备份 (crontab 每 5 分钟)
  $0 list                  列出所有备份
  $0 latest                打印最近一次备份路径 + manifest
  $0 verify [备份目录]     校验完整性 (默认 latest)
  $0 purge [保留份数=10]   清理旧备份
环境变量:
  AWD_BACKUP_DIR=/tmp/awd_backup
  AWD_WEB_ROOT=/app
  AWD_DB_NAME=xyhcms
  AWD_DB_USER=cms
  AWD_DB_PASS=             (留空会自动从 /app/*/Conf/db.php 读取)
EOF
    exit 1
    ;;
esac
