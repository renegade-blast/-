#!/bin/bash
# AWD Redis 未授权访问 - 自动加固脚本
#
# 检测 + 加固 + 验证 三步走:
#   1. 检测 Redis 是否暴露未授权 (无密码/绑 0.0.0.0/默认端口/危险命令未禁)
#   2. 自动加固 (改 bind/设密码/改端口/禁危险命令/最小权限/防火墙)
#   3. 验证加固效果 (本地连通 + 远程拒绝 + INFO keyspace 拒绝)
#
# 用法:
#   bash redis_harden.sh                # 自动检测 + 交互式加固
#   bash redis_harden.sh --auto         # 全自动加固 (使用默认强密码, 适合脚本调用)
#   bash redis_harden.sh --check        # 仅检测, 不修改 (赛前自查)
#   bash redis_harden.sh --rollback     # 回滚到加固前状态
#   bash redis_harden.sh --help
#
# 环境变量 (覆盖默认值):
#   REDIS_BIND=127.0.0.1                # 绑定 IP
#   REDIS_PORT=6380                     # 新端口 (默认改 6380 避开扫描器)
#   REDIS_PASSWORD=Rds#2026$tr0ng!Pass  # 强密码
#   REDIS_CONFIG=/etc/redis/redis.conf  # 配置文件路径
#   REDIS_SERVICE=redis-server          # systemd 服务名

set -u

# ===== 默认配置 =====
REDIS_BIND="${REDIS_BIND:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6380}"
REDIS_PASSWORD="${REDIS_PASSWORD:-Rds#2026\$tr0ng!Pass}"
REDIS_CONFIG="${REDIS_CONFIG:-/etc/redis/redis.conf}"
REDIS_SERVICE="${REDIS_SERVICE:-redis-server}"
BACKUP_DIR="/tmp/awd_redis_backup"
BACKUP_TS=$(date '+%Y%m%d_%H%M%S')

# ===== 颜色 =====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*"; }
section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# ===== 步骤 1: 检测 =====
detect_redis() {
  section "Step 1: 检测 Redis 当前状态"

  local has_issue=0

  # 1.1 是否安装
  if ! command -v redis-cli &>/dev/null && ! command -v redis-server &>/dev/null; then
    warn "未检测到 Redis 安装 (redis-cli/redis-server 都不存在)"
    echo "    如果靶机不跑 Redis, 可忽略此脚本"
    return 255
  fi
  ok "Redis 已安装: $(redis-server --version 2>/dev/null || echo 'version?')"

  # 1.2 是否在运行
  local pid=""
  if pgrep -x redis-server &>/dev/null; then
    pid=$(pgrep -x redis-server | head -1)
    ok "Redis 进程运行中 (PID=$pid)"
  else
    warn "Redis 进程未运行"
    if [ -f "$REDIS_CONFIG" ]; then
      echo "    但配置文件存在: $REDIS_CONFIG"
    fi
    return 1
  fi

  # 1.3 监听地址和端口
  echo
  echo "当前监听情况:"
  ss -tlnp 2>/dev/null | grep -E "redis|:6379|:6380" || \
    netstat -tlnp 2>/dev/null | grep -E "redis|:6379|:6380"
  echo

  # 1.4 检查配置文件
  local cfg_file=""
  for f in "$REDIS_CONFIG" /etc/redis/redis.conf /etc/redis.conf /usr/local/etc/redis.conf; do
    [ -f "$f" ] && { cfg_file="$f"; break; }
  done

  if [ -n "$cfg_file" ]; then
    ok "配置文件: $cfg_file"
    echo "  关键配置 (注释行已过滤):"
    grep -vE "^\s*#|^\s*$" "$cfg_file" | grep -iE "^(bind|port|requirepass|protected-mode|rename-command|dir|dbfilename)" | head -15 | sed 's/^/    /'
    echo
  else
    warn "未找到 redis.conf, Redis 可能用命令行参数启动"
  fi

  # 1.5 实际未授权检测 (无密码能不能连)
  echo "未授权访问检测:"
  local cli_port
  cli_port=$(ss -tlnp 2>/dev/null | grep redis | grep -oE ':[0-9]+' | head -1 | tr -d ':')
  [ -z "$cli_port" ] && cli_port=6379

  if command -v redis-cli &>/dev/null; then
    # 不带密码连接
    local resp
    resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$cli_port" PING 2>/dev/null)
    if [ "$resp" = "PONG" ]; then
      err "⚠️  无密码即可连接 (port $cli_port) → 未授权!"
      echo "    攻击者可: 写 SSH 公钥 / 写 Webshell / 写 Crontab / 主从复制 RCE"
      has_issue=1

      # 进一步探测危险配置
      local cfg_dir cfg_dbfile
      cfg_dir=$(timeout 3 redis-cli -h 127.0.0.1 -p "$cli_port" CONFIG GET dir 2>/dev/null | tail -1)
      cfg_dbfile=$(timeout 3 redis-cli -h 127.0.0.1 -p "$cli_port" CONFIG GET dbfilename 2>/dev/null | tail -1)
      echo "    当前 dir        = $cfg_dir"
      echo "    当前 dbfilename = $cfg_dbfile"
      echo "    若 dir 可写 + dbfilename=*.php → 直接写 Webshell"
    else
      ok "无密码连接被拒 (resp=$resp) → 已设密码或 protected-mode"
    fi

    # 检测 protected-mode
    local pm
    pm=$(timeout 3 redis-cli -h 127.0.0.1 -p "$cli_port" CONFIG GET protected-mode 2>/dev/null | tail -1)
    [ -n "$pm" ] && echo "    protected-mode = $pm"
  fi

  # 1.6 外部可达性 (从 0.0.0.0 监听判断)
  # ss 输出第 4 列是本地地址, 形如 127.0.0.1:6379 / [::1]:6379 / 0.0.0.0:6379 / *:6379 / [::]:6379
  # 安全: 127.0.0.1 / [::1] (本地回环)
  # 危险: 0.0.0.0 / * / [::] (全网卡)
  local listen_addrs
  listen_addrs=$(ss -tlnH 2>/dev/null | awk '$4 ~ /:(6379|6380)$/ {print $4}')
  if echo "$listen_addrs" | grep -qE "^(0\.0\.0\.0|\*|\[::\]):"; then
    err "⚠️  Redis 绑定 0.0.0.0 / [::] / * (全网卡) → 外网可直连"
    echo "    监听地址: $(echo "$listen_addrs" | tr '\n' ' ')"
    has_issue=1
  elif echo "$listen_addrs" | grep -qE "^(127\.0\.0\.1|\[::1\]):"; then
    ok "仅监听本地回环 (127.0.0.1 / [::1])"
  fi
  # [::1] 是 IPv6 本地回环, 安全, 不报警

  return $has_issue
}

# ===== 步骤 2: 备份配置 =====
backup_config() {
  section "Step 2: 备份当前配置 (便于回滚)"

  mkdir -p "$BACKUP_DIR"
  local cfg_file=""
  for f in "$REDIS_CONFIG" /etc/redis/redis.conf /etc/redis.conf /usr/local/etc/redis.conf; do
    [ -f "$f" ] && { cfg_file="$f"; break; }
  done

  if [ -n "$cfg_file" ]; then
    local bak="$BACKUP_DIR/redis_conf_${BACKUP_TS}.bak"
    cp -a "$cfg_file" "$bak"
    ok "已备份: $bak"
    echo "$cfg_file" > "$BACKUP_DIR/config_path.txt"
    echo "$bak" > "$BACKUP_DIR/latest_backup.txt"
    # 保存当前运行时配置快照
    if command -v redis-cli &>/dev/null; then
      local port
      port=$(ss -tlnp 2>/dev/null | grep redis | grep -oE ':[0-9]+' | head -1 | tr -d ':')
      [ -z "$port" ] && port=6379
      redis-cli -h 127.0.0.1 -p "$port" CONFIG GET '*' > "$BACKUP_DIR/runtime_config_${BACKUP_TS}.txt" 2>/dev/null || true
    fi
  else
    warn "未找到配置文件, 跳过备份"
  fi
}

# ===== 步骤 3: 加固 =====
harden_redis() {
  section "Step 3: 加固 Redis"

  local cfg_file=""
  for f in "$REDIS_CONFIG" /etc/redis/redis.conf /etc/redis.conf /usr/local/etc/redis.conf; do
    [ -f "$f" ] && { cfg_file="$f"; break; }
  done

  if [ -z "$cfg_file" ]; then
    err "找不到 redis.conf, 无法加固"
    warn "如果是 Docker 容器, 配置可能在 /usr/local/etc/redis/redis.conf"
    warn "或 Redis 通过命令行 --port --requirepass 启动, 需改启动脚本"
    return 1
  fi

  # 3.1 bind 127.0.0.1
  log "[3.1] 设置 bind = $REDIS_BIND"
  if grep -qE "^\s*bind\s+" "$cfg_file"; then
    sed -i -E "s|^\s*bind\s+.*|bind $REDIS_BIND|" "$cfg_file"
  else
    echo "bind $REDIS_BIND" >> "$cfg_file"
  fi
  ok "bind 已设为 $REDIS_BIND (仅本地访问)"

  # 3.2 protected-mode yes
  log "[3.2] 开启 protected-mode"
  if grep -qE "^\s*protected-mode\s+" "$cfg_file"; then
    sed -i -E "s|^\s*protected-mode\s+.*|protected-mode yes|" "$cfg_file"
  else
    echo "protected-mode yes" >> "$cfg_file"
  fi
  ok "protected-mode = yes (即使外网连也拒绝)"

  # 3.3 改端口 (默认 6380, 避开扫描器对 6379 的探测)
  log "[3.3] 改端口 $REDIS_PORT (避开 6379 扫描)"
  if grep -qE "^\s*port\s+" "$cfg_file"; then
    sed -i -E "s|^\s*port\s+.*|port $REDIS_PORT|" "$cfg_file"
  else
    echo "port $REDIS_PORT" >> "$cfg_file"
  fi
  ok "port = $REDIS_PORT"

  # 3.4 设密码
  log "[3.4] 设置 requirepass"
  # 密码含 $ 需要特殊处理: sed 用 | 作为分隔符, & 在 replacement 中需转义
  local safe_pass
  safe_pass=$(printf '%s\n' "$REDIS_PASSWORD" | sed 's/[&|]/\\&/g')
  if grep -qE "^\s*requirepass\s+" "$cfg_file"; then
    sed -i -E "s|^\s*requirepass\s+.*|requirepass $safe_pass|" "$cfg_file"
  else
    echo "requirepass $safe_pass" >> "$cfg_file"
  fi
  ok "requirepass 已设置 (密码长度: ${#REDIS_PASSWORD})"

  # 3.5 禁用危险命令
  log "[3.5] 禁用危险命令 (CONFIG/FLUSHALL/FLUSHDB/KEYS)"
  # 先删除已有的 rename-command 行 (避免重复)
  sed -i -E '/^\s*rename-command\s+(CONFIG|FLUSHALL|FLUSHDB|KEYS)\s/d' "$cfg_file"
  cat >> "$cfg_file" <<EOF

# ===== AWD Redis 加固 (添加于 $(date '+%Y-%m-%d %H:%M:%S')) =====
rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""
EOF
  ok "已禁用: CONFIG / FLUSHALL / FLUSHDB / KEYS"

  # 3.6 限制最大内存 (防止 OOM 影响其他服务)
  log "[3.6] 限制最大内存 256MB"
  if grep -qE "^\s*maxmemory\s+" "$cfg_file"; then
    sed -i -E "s|^\s*maxmemory\s+.*|maxmemory 256mb|" "$cfg_file"
  else
    echo "maxmemory 256mb" >> "$cfg_file"
  fi
  if grep -qE "^\s*maxmemory-policy\s+" "$cfg_file"; then
    sed -i -E "s|^\s*maxmemory-policy\s+.*|maxmemory-policy allkeys-lru|" "$cfg_file"
  else
    echo "maxmemory-policy allkeys-lru" >> "$cfg_file"
  fi
  ok "maxmemory = 256mb (LRU 淘汰)"

  # 3.7 修改 dir 到专用目录 (防止写 SSH/Webshell)
  log "[3.7] 限制 RDB 文件保存目录"
  mkdir -p /var/lib/redis
  chown redis:redis /var/lib/redis 2>/dev/null || true
  if grep -qE "^\s*dir\s+" "$cfg_file"; then
    sed -i -E "s|^\s*dir\s+.*|dir /var/lib/redis|" "$cfg_file"
  else
    echo "dir /var/lib/redis" >> "$cfg_file"
  fi
  if grep -qE "^\s*dbfilename\s+" "$cfg_file"; then
    sed -i -E "s|^\s*dbfilename\s+.*|dbfilename dump.rdb|" "$cfg_file"
  else
    echo "dbfilename dump.rdb" >> "$cfg_file"
  fi
  ok "dir = /var/lib/redis (不再可写到 /root/.ssh 或 /app)"

  # 3.8 日志
  log "[3.8] 启用日志"
  if grep -qE "^\s*logfile\s+" "$cfg_file"; then
    sed -i -E "s|^\s*logfile\s+.*|logfile /var/log/redis/redis-server.log|" "$cfg_file"
  else
    echo "logfile /var/log/redis/redis-server.log" >> "$cfg_file"
  fi
  mkdir -p /var/log/redis
  chown redis:redis /var/log/redis 2>/dev/null || true
  ok "logfile = /var/log/redis/redis-server.log"

  # 3.9 防火墙 (双重保险, 即使配置错了也封掉)
  log "[3.9] iptables 加固 (封掉外部访问 6379/6380)"
  if command -v iptables &>/dev/null; then
    # 允许本地回环
    iptables -C INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT 2>/dev/null || \
      iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
    iptables -C INPUT -p tcp --dport 6380 -s 127.0.0.1 -j ACCEPT 2>/dev/null || \
      iptables -A INPUT -p tcp --dport 6380 -s 127.0.0.1 -j ACCEPT
    # 拒绝外部
    iptables -C INPUT -p tcp --dport 6379 -j DROP 2>/dev/null || \
      iptables -A INPUT -p tcp --dport 6379 -j DROP -m comment --comment "awd:redis_deny"
    iptables -C INPUT -p tcp --dport 6380 -j DROP 2>/dev/null || \
      iptables -A INPUT -p tcp --dport 6380 -j DROP -m comment --comment "awd:redis_deny"
    ok "iptables 已封 6379/6380 外部访问"
  else
    warn "iptables 不可用, 跳过防火墙规则"
  fi

  echo
  echo "加固摘要:"
  echo "  bind            = $REDIS_BIND"
  echo "  port            = $REDIS_PORT"
  echo "  requirepass     = **** (长度 ${#REDIS_PASSWORD})"
  echo "  protected-mode  = yes"
  echo "  rename-command  = CONFIG/FLUSHALL/FLUSHDB/KEYS 已禁"
  echo "  maxmemory       = 256mb (LRU)"
  echo "  dir             = /var/lib/redis (隔离 RDB 写入)"
  echo "  iptables        = 6379/6380 仅本地"
}

# ===== 步骤 4: 重启 Redis =====
restart_redis() {
  section "Step 4: 重启 Redis 服务"

  if command -v systemctl &>/dev/null && systemctl list-unit-files 2>/dev/null | grep -q "$REDIS_SERVICE"; then
    log "通过 systemctl 重启 $REDIS_SERVICE..."
    systemctl restart "$REDIS_SERVICE"
    sleep 2
    if systemctl is-active --quiet "$REDIS_SERVICE"; then
      ok "Redis 已重启 (systemctl)"
    else
      err "重启失败, 查看日志: journalctl -u $REDIS_SERVICE -n 30"
      return 1
    fi
  elif command -v service &>/dev/null; then
    log "通过 service 重启..."
    service "$REDIS_SERVICE" restart 2>/dev/null && ok "Redis 已重启 (service)" || {
      warn "service 重启失败, 尝试直接 kill+重启"
      pkill -9 redis-server 2>/dev/null
      sleep 1
      # 用配置文件启动
      local cfg_file=""
      for f in "$REDIS_CONFIG" /etc/redis/redis.conf /etc/redis.conf; do
        [ -f "$f" ] && { cfg_file="$f"; break; }
      done
      if [ -n "$cfg_file" ] && command -v redis-server &>/dev/null; then
        nohup redis-server "$cfg_file" --daemonize yes >/dev/null 2>&1 &
        sleep 2
        pgrep -x redis-server &>/dev/null && ok "Redis 已手动重启" || err "手动重启失败"
      fi
    }
  else
    warn "无 systemctl/service, 直接 kill + 配置文件启动"
    pkill -9 redis-server 2>/dev/null
    sleep 1
    local cfg_file=""
    for f in "$REDIS_CONFIG" /etc/redis/redis.conf /etc/redis.conf; do
      [ -f "$f" ] && { cfg_file="$f"; break; }
    done
    [ -n "$cfg_file" ] && nohup redis-server "$cfg_file" --daemonize yes >/dev/null 2>&1 &
    sleep 2
  fi
}

# ===== 步骤 5: 验证 =====
verify_harden() {
  section "Step 5: 验证加固效果"

  local pass=0 fail=0

  # 5.1 进程是否在跑
  if pgrep -x redis-server &>/dev/null; then
    ok "Redis 进程运行中 (PID=$(pgrep -x redis-server | head -1))"
    pass=$((pass+1))
  else
    err "Redis 进程未运行"
    fail=$((fail+1))
    return 1
  fi

  # 5.2 监听端口
  if ss -tlnp 2>/dev/null | grep -q ":$REDIS_PORT "; then
    ok "端口 $REDIS_PORT 监听中"
    pass=$((pass+1))
  else
    err "端口 $REDIS_PORT 未监听"
    fail=$((fail+1))
  fi

  # 5.3 监听地址不是 0.0.0.0
  local listen_line
  listen_line=$(ss -tlnp 2>/dev/null | grep ":$REDIS_PORT " | head -1)
  if echo "$listen_line" | grep -qE "127\.0\.0\.1|\[::1\]"; then
    ok "仅监听本地: $listen_line"
    pass=$((pass+1))
  elif echo "$listen_line" | grep -qE "0\.0\.0\.0|\*|::"; then
    err "仍监听 0.0.0.0: $listen_line"
    fail=$((fail+1))
  fi

  # 5.4 无密码连接应该失败
  if command -v redis-cli &>/dev/null; then
    log "测试无密码连接 (应该被拒绝)..."
    local resp
    resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$REDIS_PORT" PING 2>/dev/null)
    if [ "$resp" = "PONG" ]; then
      err "⚠️  无密码仍可 PING → 加固失败!"
      fail=$((fail+1))
    elif echo "$resp" | grep -qi "NOAUTH\|Authentication"; then
      ok "无密码被拒 (NOAUTH) → 密码生效"
      pass=$((pass+1))
    else
      warn "无密码连接响应: $resp"
    fi

    # 5.5 用密码连接应该成功
    log "测试带密码连接..."
    resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$REDIS_PORT" -a "$REDIS_PASSWORD" --no-auth-warning PING 2>/dev/null)
    if [ "$resp" = "PONG" ]; then
      ok "带密码连接成功 (PONG) → 密码正确"
      pass=$((pass+1))
    else
      err "带密码连接失败: $resp"
      fail=$((fail+1))
    fi

    # 5.6 危险命令应该被禁
    log "测试 CONFIG 命令 (应该被拒)..."
    resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$REDIS_PORT" -a "$REDIS_PASSWORD" --no-auth-warning CONFIG GET dir 2>/dev/null)
    if echo "$resp" | grep -qiE "unknown|disabled|ERR"; then
      ok "CONFIG 命令已被禁用 → 防写 Webshell/公钥"
      pass=$((pass+1))
    else
      err "CONFIG 命令仍可用: $resp"
      fail=$((fail+1))
    fi

    # 5.7 FLUSHALL 应该被禁
    log "测试 FLUSHALL 命令 (应该被拒)..."
    resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$REDIS_PORT" -a "$REDIS_PASSWORD" --no-auth-warning FLUSHALL 2>/dev/null)
    if echo "$resp" | grep -qiE "unknown|disabled|ERR"; then
      ok "FLUSHALL 已禁用 → 防清库"
      pass=$((pass+1))
    else
      err "FLUSHALL 仍可用: $resp"
      fail=$((fail+1))
    fi

    # 5.8 dir 不再指向敏感目录
    log "检查 RDB 保存目录..."
    local cfg_file
    cfg_file=$(grep -E "^\s*dir\s+" /etc/redis/redis.conf 2>/dev/null | head -1 | awk '{print $2}')
    if echo "$cfg_file" | grep -qE "/var/lib/redis|/tmp"; then
      ok "dir = $cfg_file (安全, 不在 /root/.ssh 或 /app)"
      pass=$((pass+1))
    elif echo "$cfg_file" | grep -qE "/root|/home|/app|/var/www"; then
      err "dir = $cfg_file (危险! 可能被用来写 SSH 公钥或 Webshell)"
      fail=$((fail+1))
    fi
  fi

  # 总结
  echo
  if [ "$fail" = 0 ]; then
    ok "🎉 全部通过 ($pass 项)"
    echo
    echo "=== 加固后连接信息 (请记录) ==="
    echo "  主机: 127.0.0.1"
    echo "  端口: $REDIS_PORT  (不再是默认 6379)"
    echo "  密码: $REDIS_PASSWORD"
    echo
    echo "  PHP 连接示例:"
    echo "    \$redis = new Redis();"
    echo "    \$redis->connect('127.0.0.1', $REDIS_PORT);"
    echo "    \$redis->auth('$REDIS_PASSWORD');"
    echo
    echo "  命令行连接:"
    echo "    redis-cli -h 127.0.0.1 -p $REDIS_PORT -a '$REDIS_PASSWORD'"
    echo
    warn "⚠️  务必同步修改业务代码中的 Redis 连接配置!"
    warn "    搜索: grep -rn '6379' /app --include='*.php'"
    warn "    搜索: grep -rn 'redis' /app --include='*.php'"
  else
    err "❌ $fail 项失败, $pass 项通过"
    warn "查看日志: journalctl -u $REDIS_SERVICE -n 30"
    return 1
  fi
}

# ===== 回滚 =====
rollback() {
  section "回滚 Redis 配置"

  if [ ! -f "$BACKUP_DIR/latest_backup.txt" ]; then
    err "未找到备份记录: $BACKUP_DIR/latest_backup.txt"
    return 1
  fi

  local bak cfg_file
  bak=$(cat "$BACKUP_DIR/latest_backup.txt")
  cfg_file=$(cat "$BACKUP_DIR/config_path.txt" 2>/dev/null || echo "$REDIS_CONFIG")

  if [ ! -f "$bak" ]; then
    err "备份文件不存在: $bak"
    return 1
  fi

  warn "将恢复: $cfg_file ← $bak"
  read -p "确认回滚? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "已取消"
    return 1
  fi

  cp -a "$bak" "$cfg_file"
  ok "配置已回滚"

  if command -v systemctl &>/dev/null; then
    systemctl restart "$REDIS_SERVICE"
  else
    pkill -9 redis-server; sleep 1
    nohup redis-server "$cfg_file" --daemonize yes >/dev/null 2>&1 &
  fi
  sleep 2
  ok "Redis 已用旧配置重启"
}

# ===== 主入口 =====
main() {
  local action="${1:-interactive}"

  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════╗"
  echo "║   AWD Redis 未授权访问 - 自动加固脚本      ║"
  echo "╚════════════════════════════════════════════╝"
  echo -e "${NC}"

  case "$action" in
    --check|check)
      detect_redis
      ;;
    --auto|auto)
      detect_redis
      local detect_rc=$?
      [ "$detect_rc" = "255" ] && { warn "Redis 未安装, 退出"; exit 0; }
      [ "$detect_rc" = "0" ] && { ok "未检测到未授权问题, 无需加固"; exit 0; }
      backup_config
      harden_redis
      restart_redis
      verify_harden
      ;;
    --rollback|rollback)
      rollback
      ;;
    --help|help|-h)
      cat <<EOF
用法:
  $0                交互模式: 检测 + 询问后加固
  $0 --auto         全自动: 检测 → 备份 → 加固 → 重启 → 验证
  $0 --check        仅检测, 不修改 (赛前自查)
  $0 --rollback     回滚到加固前配置
  $0 --help         显示帮助

环境变量:
  REDIS_BIND=127.0.0.1                绑定 IP (默认 127.0.0.1)
  REDIS_PORT=6380                     新端口 (默认 6380, 避开扫描)
  REDIS_PASSWORD=Rds#2026\$tr0ng!Pass  强密码 (默认值含大小写+数字+特殊)
  REDIS_CONFIG=/etc/redis/redis.conf  配置文件路径
  REDIS_SERVICE=redis-server          systemd 服务名

加固内容:
  1. bind 127.0.0.1 (禁止外网)
  2. protected-mode yes
  3. 改端口 6379 → 6380 (避开扫描器)
  4. 设强密码 requirepass
  5. 禁用 CONFIG/FLUSHALL/FLUSHDB/KEYS 命令
  6. maxmemory 256mb + LRU (防 OOM)
  7. dir = /var/lib/redis (隔离 RDB, 防 SSH/Webshell 写入)
  8. iptables 封 6379/6380 外部访问 (双重保险)
EOF
      ;;
    interactive|"")
      detect_redis
      local detect_rc=$?
      if [ "$detect_rc" = "255" ]; then
        warn "Redis 未安装, 退出"
        exit 0
      fi
      if [ "$detect_rc" = "0" ]; then
        ok "未检测到未授权问题"
        read -p "仍要强制加固? [y/N]: " force
        [[ ! "$force" =~ ^[Yy]$ ]] && exit 0
      else
        echo
        warn "检测到未授权问题, 建议立即加固"
        read -p "开始加固? [Y/n]: " confirm
        [[ "$confirm" =~ ^[Nn]$ ]] && { echo "已取消"; exit 0; }
      fi

      read -p "新端口 [$REDIS_PORT]: " in_port
      [ -n "$in_port" ] && REDIS_PORT="$in_port"
      read -p "新密码 [默认强密码]: " in_pass
      [ -n "$in_pass" ] && REDIS_PASSWORD="$in_pass"

      backup_config
      harden_redis
      restart_redis
      verify_harden
      ;;
    *)
      err "未知参数: $action"
      echo "运行 $0 --help 查看用法"
      exit 1
      ;;
  esac
}

main "$@"
