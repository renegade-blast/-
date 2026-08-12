#!/bin/bash
# AWD 实时流量监控 + 非白名单 IP 自动封禁
# - 支持 Apache access.log / Nginx access.log / 自定义日志
# - 实时提取每一条请求的客户端 IP
# - 决策：调用 ip_firewall.py check $ip
#   * 白名单 → 放行
#   * 黑名单/默认deny策略命中 → 立即调用 auto-ban 拉黑 (iptables DROP + 黑名单 + 写日志)
# - 额外：速率阈值检测（路径爆破），同一 IP 短时间 > N 条 直接封
#
# 用法:
#   前台: bash traffic_monitor.sh start /var/log/apache2/access.log combined
#   后台: bash traffic_monitor.sh daemon /var/log/apache2/access.log combined
#   停止: bash traffic_monitor.sh stop
#   状态: bash traffic_monitor.sh status
#   也支持多日志 (空格分隔):
#     bash traffic_monitor.sh daemon "/var/log/apache2/access.log /var/log/nginx/access.log" combined
#
# 日志格式: combined | common | nginx | simple  (默认 auto 自动探测)

set -u

ACTION="${1:-status}"
LOG_PATHS="${2:-/var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log /app/Runtime/Logs/access.log}"
LOG_FMT="${3:-auto}"

IPFW="$(cd "$(dirname "$0")" && pwd)/ip_firewall.py"
if [ ! -f "$IPFW" ]; then
  IPFW="/tmp/ip_firewall.py"
fi

# 凭据提取器 (从流量中嗅探密码并逆向解码)
CRED_EXTRACTOR="$(cd "$(dirname "$0")" && pwd)/../attack/credential_extractor.py"
if [ ! -f "$CRED_EXTRACTOR" ]; then
  CRED_EXTRACTOR="/tmp/credential_extractor.py"
fi

AWD_IPFW_DIR="${AWD_IPFW_DIR:-/tmp/awd_ipfw}"
export AWD_IPFW_DIR
mkdir -p "$AWD_IPFW_DIR"

PID_FILE="$AWD_IPFW_DIR/traffic_monitor.pid"
RUN_LOG="$AWD_IPFW_DIR/traffic_monitor.log"
STATE_DIR="$AWD_IPFW_DIR/state"
mkdir -p "$STATE_DIR"

# 凭据嗅探相关文件
CRED_LOG="$AWD_IPFW_DIR/credentials.log"          # 最终解码结果日志
CRED_CANDIDATES="$STATE_DIR/cred_candidates.txt"  # 待解码的密码候选 (每行一个值)
CRED_SEEN="$STATE_DIR/cred_seen.txt"              # 已处理的密码值 (去重)
CRED_COUNT=0                                       # 自上次 flush 以来的新候选数
CRED_FLUSH_THRESHOLD="${CRED_FLUSH_THRESHOLD:-10}" # 积累 N 个候选后批量解码

# 速率阈值 (RATE_WINDOW_SEC 秒内超过 RATE_MAX_HITS 次即封)
RATE_WINDOW_SEC="${RATE_WINDOW_SEC:-10}"
RATE_MAX_HITS="${RATE_MAX_HITS:-50}"
# 去重冷却窗口（秒）：同一IP被封一次后，N秒内不再重复ban
BAN_COOLDOWN_SEC="${BAN_COOLDOWN_SEC:-1800}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$RUN_LOG"; }

detect_format() {
  local f="$1"
  [ -f "$f" ] || return 1
  local sample
  sample=$(tail -n 5 "$f" 2>/dev/null | grep -v "^$" | head -1)
  [ -z "$sample" ] && return 1
  # combined/nginx: IP - - [date] "METHOD /path HTTP/x" 200 1234 "ref" "UA"
  if echo "$sample" | grep -qE '^[0-9a-fA-F.:]+ [^ ]+ [^ ]+ \[[^]]+\] "[A-Z]+ [^"]* HTTP/[0-9.]+" [0-9]+ [0-9"-]+'; then
    if echo "$sample" | grep -qE '"-" "[^"]*"$'; then
      echo "combined"
    else
      echo "nginx"
    fi
    return 0
  fi
  # common: 无 UA/ref
  if echo "$sample" | grep -qE '^[0-9a-fA-F.:]+ [^ ]+ [^ ]+ \[[^]]+\] "[A-Z]+ [^"]* HTTP/[0-9.]+" [0-9]+ [0-9-]+'; then
    echo "common"
    return 0
  fi
  # simple: 只有 IP ...
  if echo "$sample" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}'; then
    echo "simple"
    return 0
  fi
  echo "unknown"
}

extract_ip() {
  local line="$1" fmt="$2"
  case "$fmt" in
    combined|nginx|common|auto)
      # awk 第1列
      echo "$line" | awk '{print $1}' | tr -d '\r'
      ;;
    simple)
      echo "$line" | awk '{print $1}' | tr -d '\r'
      ;;
    *)
      echo "$line" | awk '{print $1}' | tr -d '\r'
      ;;
  esac
}

# 用 Python 3 层判断决策 (白名单→放行，否则封禁)
# 返回: 0=ALLOW  1=BLOCK
check_ip_decision() {
  local ip="$1"
  if [ ! -f "$IPFW" ]; then
    # 无 ip_firewall.py 时 fallback: 只允许 127.0.0.1
    [ "$ip" = "127.0.0.1" ] && return 0
    return 1
  fi
  python3 "$IPFW" check "$ip" >/dev/null 2>&1
  return $?
}

# 检查该IP是否需要触发速率封禁
rate_limit_check_and_ban() {
  local ip="$1"
  local now key win_count
  now=$(date +%s)
  key=$(printf "%x" "$((now / RATE_WINDOW_SEC))")
  local file="$STATE_DIR/rate_${key}_${ip//[:.]/_}"
  # 原子+1
  if [ -f "$file" ]; then
    win_count=$(($(cat "$file" 2>/dev/null || echo 0) + 1))
  else
    win_count=1
  fi
  echo "$win_count" > "$file" 2>/dev/null || true
  # 清理旧窗口
  find "$STATE_DIR" -maxdepth 1 -name 'rate_*' -type f -mmin +$((RATE_WINDOW_SEC*2/60+1)) -delete 2>/dev/null || true

  if [ "$win_count" -ge "$RATE_MAX_HITS" ]; then
    log "🚨 速率超限: $ip $win_count/$RATE_MAX_HITS hits in ${RATE_WINDOW_SEC}s → 自动封禁"
    do_ban "$ip" "rate_exceed:${win_count}/${RATE_MAX_HITS}in${RATE_WINDOW_SEC}s"
    return 0
  fi
  return 1
}

# 执行封禁 (去重)
do_ban() {
  local ip="$1" reason="$2"
  local cool_file="$STATE_DIR/ban_cool_${ip//[:.]/_}"
  if [ -f "$cool_file" ]; then
    # 冷却中
    local ts
    ts=$(cat "$cool_file" 2>/dev/null || echo 0)
    local now diff
    now=$(date +%s)
    diff=$((now - ts))
    if [ "$diff" -lt "$BAN_COOLDOWN_SEC" ]; then
      return 0  # 冷却中，跳过
    fi
  fi
  echo "$(date +%s)" > "$cool_file" 2>/dev/null || true
  if [ -f "$IPFW" ]; then
    python3 "$IPFW" auto-ban "$ip" "$reason" >>"$RUN_LOG" 2>&1 || true
  else
    # fallback iptables
    iptables -I INPUT -s "$ip" -j DROP -m comment --comment "awd:autoban:$reason" 2>/dev/null || true
  fi
  log "🚫 BAN $ip  reason=$reason"
}

# ================================================================
# 密码嗅探: 从 HTTP 请求中提取攻击者留下的密码参数
# ================================================================
# URL decode (%XX → 字符)
urldecode() {
  local s="$1" out=""
  local i=0 len=${#s}
  while [ $i -lt $len ]; do
    local c="${s:$i:1}"
    if [ "$c" = "%" ] && [ $((i + 2)) -le $len ]; then
      local hex="${s:$((i+1)):2}"
      out+="$(printf "\\x$hex" 2>/dev/null || echo "%$hex")"
      i=$((i + 3))
    else
      out+="$c"
      i=$((i + 1))
    fi
  done
  printf '%s' "$out"
}

# 从单行日志中嗅探密码参数
sniff_credentials() {
  local line="$1" ip="$2" src="$3"
  # 快速预筛: 不含密码关键词直接返回 (避免对每行都做复杂解析)
  echo "$line" | grep -qiE '(password|passwd|pass|pwd|secret|token|auth|requirepass|apikey|api_key)=' || return 0
  # 排除 "auth=" 出现在非参数上下文 (如 HTTP header 名)

  # 1. 从请求行提取 query string: "GET /path?key=val HTTP/1.1"
  local req_query
  req_query=$(echo "$line" | grep -oiE '"[A-Z]+ [^"]* HTTP/[0-9.]+"' | head -1)
  [ -n "$req_query" ] && _extract_pwd_params "$req_query" "$ip" "$src"

  # 2. 从 referer 提取
  local ref
  ref=$(echo "$line" | grep -oiE '"https?://[^"]*\?[^"]*"' | head -1)
  [ -n "$ref" ] && _extract_pwd_params "$ref" "$ip" "$src"

  # 3. 从 HTTP Basic Auth (Authorization: Basic xxx) 提取 — 某些日志格式会记录
  local b64auth
  b64auth=$(echo "$line" | grep -oiE 'Authorization:[^"]*Basic[[:space:]]+[A-Za-z0-9+/=]+' | grep -oiE '[A-Za-z0-9+/=]{8,}$')
  if [ -n "$b64auth" ]; then
    local decoded
    decoded=$(echo "$b64auth" | base64 -d 2>/dev/null)
    if [ -n "$decoded" ] && echo "$decoded" | grep -q ':'; then
      local user="${decoded%%:*}" pass="${decoded#*:}"
      [ -n "$pass" ] && _record_cred_candidate "$pass" "$ip" "$src" "BasicAuth($user)"
    fi
  fi
}

# 从一段文本里提取 password=xxx 等参数值
_extract_pwd_params() {
  local text="$1" ip="$2" src="$3"
  # 匹配 key=value, value 到 & 或空格或引号结束 (用 [:space:] 代替 \s, grep -E 不支持 \s)
  local matches
  matches=$(echo "$text" | grep -oiE '(password|passwd|pass|pwd|secret|token|auth|requirepass|apikey|api_key)=[^&[:space:]"\\]+' || true)
  [ -z "$matches" ] && return 0
  local kv
  for kv in $matches; do
    # 必须含 = (排除 HTTP/1.1 等无 = 的误匹配)
    [[ "$kv" != *=* ]] && continue
    local key="${kv%%=*}" val="${kv#*=}"
    # URL decode
    val=$(urldecode "$val")
    # 过滤明显非密码 (太短/纯路径/HTTP版本号)
    [ ${#val} -lt 2 ] && continue
    [[ "$val" == /* ]] && continue  # 路径
    [[ "$val" =~ ^HTTP/[0-9] ]] && continue  # HTTP 版本号
    _record_cred_candidate "$val" "$ip" "$src" "$key"
  done
}

# 记录密码候选 (去重)
_record_cred_candidate() {
  local val="$1" ip="$2" src="$3" keyname="$4"
  # 去重: 已处理过的跳过
  touch "$CRED_SEEN"
  if grep -qxF "$val" "$CRED_SEEN" 2>/dev/null; then
    return 0
  fi
  echo "$val" >> "$CRED_SEEN"
  echo "$val" >> "$CRED_CANDIDATES"
  CRED_COUNT=$((CRED_COUNT + 1))
  log "🔑 嗅探到密码参数: ip=$ip key=$keyname val=${val:0:80} (候选#$CRED_COUNT)"
  # 达到阈值 → 批量解码
  if [ "$CRED_COUNT" -ge "$CRED_FLUSH_THRESHOLD" ]; then
    flush_credentials
  fi
}

# 批量调用 credential_extractor.py 逆向解码候选密码
flush_credentials() {
  [ -f "$CRED_CANDIDATES" ] || return 0
  local count
  count=$(wc -l < "$CRED_CANDIDATES" 2>/dev/null || echo 0)
  [ "$count" -eq 0 ] && return 0

  if [ ! -f "$CRED_EXTRACTOR" ]; then
    log "⚠️  credential_extractor.py 不存在 ($CRED_EXTRACTOR), 跳过解码"
    > "$CRED_CANDIDATES"
    CRED_COUNT=0
    return 0
  fi

  log "🔑 批量逆向解码 $count 个密码候选..."
  {
    echo ""
    echo "================================================================"
    echo "  🔑 密码逆向解码  $(date '+%F %T')"
    echo "  候选数: $count"
    echo "================================================================"
    # 去重后逐个解码 (--dict 启用字典爆破, 哈希自动用 password_dict.txt 爆破)
    sort -u "$CRED_CANDIDATES" | while IFS= read -r val; do
      [ -z "$val" ] && continue
      python3 "$CRED_EXTRACTOR" --dict --crack "$val" 2>&1 | grep -E '(分析|候选|→|最可能|形式|明文|哈希|爆破|命中|建议)' || true
      echo "----------------------------------------------------------------"
    done
  } >> "$CRED_LOG"

  local found
  found=$(grep -cE '(最可能明文|爆破成功)' "$CRED_LOG" 2>/dev/null || echo 0)
  log "✅ 解码完成, 结果已写入 $CRED_LOG (累计发现明文 $found 个)"
  > "$CRED_CANDIDATES"
  CRED_COUNT=0
}

# 查看已发现的密码
show_credentials() {
  echo "=== AWD 流量密码嗅探结果 ==="
  echo "凭据日志: $CRED_LOG"
  echo "候选文件: $CRED_CANDIDATES"
  echo "已处理:   $(wc -l < "$CRED_SEEN" 2>/dev/null || echo 0) 个去重密码值"
  echo
  if [ -f "$CRED_LOG" ] && [ -s "$CRED_LOG" ]; then
    echo "--- 最近发现的密码 (最后 40 行) ---"
    tail -40 "$CRED_LOG"
  else
    echo "(暂无, 等待流量中出现密码参数)"
  fi
  echo
  if [ -f "$CRED_CANDIDATES" ] && [ -s "$CRED_CANDIDATES" ]; then
    local pending
    pending=$(wc -l < "$CRED_CANDIDATES")
    echo "--- 待解码候选: $pending 个 (达到 $CRED_FLUSH_THRESHOLD 个后自动解码) ---"
    tail -10 "$CRED_CANDIDATES"
    echo "  立即解码: bash $0 flush"
  fi
}

# 处理单行日志
process_line() {
  local line="$1" fmt="$2" src="$3"
  [ -z "$line" ] && return
  local ip
  ip=$(extract_ip "$line" "$fmt")
  [ -z "$ip" ] && return
  # 跳过非 IP
  if ! echo "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'; then
    return
  fi
  # 1) 速率检测 (先跑一下，超限会自动ban)
  rate_limit_check_and_ban "$ip"
  # 2) 白名单/黑名单决策
  if check_ip_decision "$ip"; then
    : # allow
  else
    log "🚫 非白名单请求拦截: src=$src ip=$ip line=${line:0:160}"
    do_ban "$ip" "not_in_whitelist:$src"
  fi
  # 3) 密码嗅探: 从请求中提取攻击者留下的密码参数
  sniff_credentials "$line" "$ip" "$src"
}

stop() {
  # 停止前 flush 剩余的密码候选
  if [ -f "$CRED_CANDIDATES" ] && [ -s "$CRED_CANDIDATES" ]; then
    log "停止前 flush 剩余密码候选..."
    flush_credentials
  fi
  if [ -f "$PID_FILE" ]; then
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      log "停止 traffic_monitor (PID=$pid)..."
      kill "$pid" 2>/dev/null
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      rm -f "$PID_FILE"
      log "已停止"
      return 0
    else
      log "PID 文件存在但进程不存在，清理"
      rm -f "$PID_FILE"
    fi
  fi
  log "未运行"
  return 0
}

status() {
  echo "=== AWD 流量监控状态 ==="
  echo "配置存储: $AWD_IPFW_DIR"
  echo "日志文件: $RUN_LOG"
  echo "IPFW脚本: $IPFW"
  echo "RATE_MAX_HITS: ${RATE_MAX_HITS}/${RATE_WINDOW_SEC}s   BAN_COOLDOWN: ${BAN_COOLDOWN_SEC}s"
  echo
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "✅ 运行中 PID=$(cat "$PID_FILE")"
    ps -fp "$(cat "$PID_FILE")" 2>/dev/null
  else
    echo "❌ 未运行"
  fi
  echo
  echo "--- 最近 20 条封禁日志 ---"
  tail -n 20 "$AWD_IPFW_DIR/ban.log" 2>/dev/null || echo "(无)"
  echo
  echo "--- 最近 10 条监控日志 ---"
  tail -n 10 "$RUN_LOG" 2>/dev/null || echo "(无)"
  echo
  if [ -f "$IPFW" ]; then
    echo "--- IP 规则摘要 ---"
    python3 "$IPFW" list 2>&1 | head -30 || true
  fi
  echo
  echo "--- 密码嗅探统计 ---"
  local seen_cnt=0 cred_cnt=0
  [ -f "$CRED_SEEN" ] && seen_cnt=$(wc -l < "$CRED_SEEN" 2>/dev/null || echo 0)
  [ -f "$CRED_LOG" ] && cred_cnt=$(grep -c '最可能明文' "$CRED_LOG" 2>/dev/null || echo 0)
  echo "已嗅探密码值: $seen_cnt 个  |  已解出明文: $cred_cnt 个"
  echo "凭据日志: $CRED_LOG"
  echo "查看详情: bash $0 creds"
}

run_foreground() {
  local log_paths="$1"
  # 解析日志格式
  declare -A fmts
  for p in $log_paths; do
    local f
    if [ "$LOG_FMT" = "auto" ]; then
      f=$(detect_format "$p")
      log "日志 $p 自动探测格式: $f"
    else
      f="$LOG_FMT"
    fi
    fmts["$p"]="$f"
  done
  log "开始实时监控: $log_paths   (按 Ctrl+C 停止)"
  [ -f "$IPFW" ] && python3 "$IPFW" list 2>/dev/null | head -6 | tee -a "$RUN_LOG"

  # tail -F 可以在轮转后继续追踪；多文件用 {} 合并
  # 用一个子 shell 把 tail -F 的输出按文件分行 tag
  while IFS= read -r line; do
    # line 可能被 tail 加前缀: "==> file <==" 或 "==> file <==content"
    local src="" content="$line"
    if echo "$line" | grep -qE '^==> .* <=='; then
      src=$(echo "$line" | sed -E 's/^==> (.*) <==$/\1/')
      continue
    fi
    local fmt="${LOG_FMT}"
    # 优先用每个文件自己的 fmt
    for p in $log_paths; do
      if [ "$p" = "$src" ]; then
        fmt="${fmts[$p]:-$LOG_FMT}"
        break
      fi
    done
    process_line "$content" "$fmt" "${src:-log}"
  done < <(tail -qF --retry -n 0 $log_paths 2>/dev/null &
           # 另加一个标记，解决多文件无法区分 src 的问题：改用每个文件单独 tail 并在前面加 tag
           echo "started")
  # 上面的单文件简单版本，下面是多文件带tag的版本
  # 简单起见，重新用正确的方式启动
}

# 正确的多文件带tag版：每个文件开一个带 awk 前缀的 tail
run_foreground_multitag() {
  local log_paths="$1"
  declare -A fmts
  local tail_pids=""
  for p in $log_paths; do
    local f
    if [ ! -r "$p" ]; then
      log "⚠️  无法读取 $p，跳过"
      continue
    fi
    if [ "$LOG_FMT" = "auto" ]; then
      f=$(detect_format "$p")
      log "📄 $p  格式探测: $f"
    else
      f="$LOG_FMT"
    fi
    fmts["$p"]="$f"
    # 后台起 tail, 每行前面加 "[SRC=p]" tag
    (
      tail -qF --retry -n 0 "$p" 2>/dev/null | while IFS= read -r line; do
        echo "[SRC=$p] $line"
      done
    ) &
    tail_pids="$tail_pids $!"
  done
  [ -f "$IPFW" ] && python3 "$IPFW" list 2>/dev/null | head -6 | tee -a "$RUN_LOG"
  log "开始实时监控 (子tail PIDs=$tail_pids)"
  echo "$tail_pids" > "$STATE_DIR/tail.pids"
  trap "log '收到信号，清理子进程...'; kill $tail_pids 2>/dev/null; rm -f '$PID_FILE'; exit 0" INT TERM EXIT

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local src="log" content="$line"
    if [[ "$line" == "[SRC="* ]]; then
      src=${line#"[SRC="}
      src=${src%%"] "*}
      content=${line#"] "}
      content=${content#"[SRC=${src}] "}
    fi
    local fmt="${fmts[$src]:-$LOG_FMT}"
    process_line "$content" "$fmt" "$src"
  done
}

case "$ACTION" in
  start|fg)
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      log "已在运行 PID=$(cat "$PID_FILE"), 先运行 stop 停止"
      exit 1
    fi
    echo $$ > "$PID_FILE"
    run_foreground_multitag "$LOG_PATHS"
    ;;
  daemon|-d)
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "已在运行 PID=$(cat "$PID_FILE")"
      exit 0
    fi
    nohup "$0" start "$LOG_PATHS" "$LOG_FMT" >>"$RUN_LOG" 2>&1 &
    disown 2>/dev/null || true
    sleep 1
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "✅ 后台启动成功 PID=$(cat "$PID_FILE")"
      echo "   日志: $RUN_LOG"
      echo "   停止: bash $0 stop"
      echo "   状态: bash $0 status"
    else
      echo "❌ 启动失败，请查看 $RUN_LOG"
      exit 1
    fi
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  creds|credentials)
    show_credentials
    ;;
  flush)
    flush_credentials
    echo "✅ 已解码, 查看: bash $0 creds"
    ;;
  *)
    cat <<EOF
用法:
  $0 start   <日志路径> [格式=auto]       前台运行
  $0 daemon  <日志路径> [格式=auto]       后台运行 (nohup)
  $0 stop                                  停止 (自动 flush 剩余密码)
  $0 status                                查看状态 + 最近封禁 + 嗅探统计
  $0 creds                                 查看嗅探到的密码 + 逆向结果
  $0 flush                                 立即解码待处理密码候选
日志路径支持多文件 (空格分隔)，例如:
  $0 daemon "/var/log/apache2/access.log /var/log/nginx/access.log"
日志格式: combined | common | nginx | simple | auto (默认)
环境变量:
  AWD_IPFW_DIR=/tmp/awd_ipfw             # 规则/状态存储目录
  RATE_WINDOW_SEC=10                     # 速率检测窗口
  RATE_MAX_HITS=50                       # 超过则自动封
  BAN_COOLDOWN_SEC=1800                  # 同IP重复封冷却
  CRED_FLUSH_THRESHOLD=10                # 积累N个密码后批量解码
EOF
    exit 1
    ;;
esac
