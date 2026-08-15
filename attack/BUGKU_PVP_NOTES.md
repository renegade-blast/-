# Bugku PVP 提交与情报备忘

## Flag 提交接口（已验证可用）
- API: `GET https://ctf.bugku.com/pvp/submit.html?token=<SUBMIT_TOKEN>&flag=flag{xxx}`
- TokeN: <SUBMIT_TOKEN>（有效，请求返回"Error FLAG"而非"竞赛不存在"）
- Flag 格式: `flag{...}` （提交 flag{test} → "Error FLAG"，即格式对内容错）

## 已确认漏洞面（全部实测）
- Web(凡诺CMS 2.1): 注入/上传/后台写文件 全封死
- pwn(9999): 无溢出/无格式串/无system RCE
- MySQL/Redis/8080/443/21: 透明代理空壳无真实服务
- SSH(22): 真实服务, 6队(31/72/98/119/189/192)全开; 弱口令爆破中但触发防爆破

## 已获得凭据/情报
- 后台口令: admin/admin (队31/72/98/119/192, 来自 install/data.sql)
- DB: cms / <DB_PASS_REDACTED> (localhost, 远程不可达)
- 源码包: /wwwroot.tar.gz (全站, 纯模板无flag)
- data.sql: 模板数据, 无flag; pwn: 无flag硬编码

## 结论
flag 在敌方容器 /flag, 需 getsell 才能读; 当前网络侧无 getshell 通路.

---

## 今日追加总结 (2026-08-14)

### SSH 爆破实证 (脚本无法提速)
- 服务器对每次失败的 password 认证强制 ~2s 节流 (实测三种配置 0.4-0.5 条/秒):
  - 每条重建连接 / 单连接复用 transport(MAX_AUTH_PER_CONN=16) / v3 复用
  - 结论: **瓶颈在服务器侧, 本地优化无效**
- 致命限制: **nohup/后台长进程在此环境会被回收**(多次实证 ps 消失, checkpoint 卡初始值), 无法静默挂几小时爆破

### 新建攻击脚本
- `attack/ssh_fast.py` — 复用 transport 连续 auth (v3), 带断点续跑
- `attack/ssh_brute_teams.py` — 多队并行慢爆控制器
- `attack/ssh_quick.py` — 单进程并发 6队x多用户, 秒测 topN 词条 (已实测: 854 组合 260s, 0 命中)
- `attack/solve_captcha.py` — 验证码/OCR (ocr_venv 环境已建)
- `attack/login_editor.py` — 后台登录尝试

### 规则词表 (基于已知线索 Nsy@Awd#2026)
- 路径: `/tmp/rule_dict.txt` (903 条)
- 覆盖: Nsy@Awd#2026 扩展 + Awd#/队号/年份/pass 组合 + 常见弱口令
- ⚠️ 已知线索 `Nsy@Awd#2026` 是大字典覆盖不到的题目生成值, 规则生成是唯一途径

### 新增漏洞审计结论 (凡诺CMS 2.1, 全部源码级确认)
- **后台上传**: `editor/phpecms/upload_json.php` 扩展名白名单无 php; **实测上传请求返回空 body** = 服务器层静默拦截上传 → 封死
- **后台登录注入**: `cms_login.php` 密码 md5 包裹 + `safe.php` 挡 and/or → 无注入
- **碎片/模板 getshell**: `cms_chip_edit.php` 只存 DB echo, 不 eval/包含 → 无码执行
- **LFI**: `index.php` $t_path/$dir 为不可控常量 → 无包含注入
- **碎片回显 XSS**: `get_chip()` 不转义 echo, 可存储 XSS 但不可 getshell

### 本地制品 flag 检索 (全部否定)
- `wwwroot.tar.gz` 全量解包 330 文件: 无 flag/ctf/key/token
- `install/data.sql` 10 表: 纯模板, 无 flag 表/内容
- `pwn` 二进制: 仅 "Welcome To WHCTF2017"
- 结论: 设计上 flag 不进 web 目录/DB (否则拖库即得 flag, 比赛失衡), 只能在容器内 RCE 读 /flag

### 当前状态
- **拿到真实 flag 数为 0** (诚实结论)
- 唯一真实服务面: SSH(22) 6队全开, 弱口令 0 命中 + 服务端节流
- 待办: 需用户/平台提供 (1)可能的 SSH 口令 (2)题目 hint 或 (3)对手容器/镜像快照下载入口

### 脚本运行提示
- 后台长进程会被回收 → 用前台同步(ssh_quick.py)短批跑, 或移步本地 kali 持久运行

---

## PWN(9999) 深度逆向分析 (2026-08-14 完整反汇编确认)

程序: `archive/192-168-1-192_src/pwn` (ELF64 / PIE / canary / stripped / 10KB)

### 函数结构 (objdump 完整反汇编)
- `b30 (0xb30)`: 帧 0xc00, canary@rbp-0x8
  - memset(src=rbp-0xbf0, 0, 0x400)
  - p=rbp-0x7f0+0x3e8 设为 "%s"(固定格式串)
  - memset(dst=rbp-0x7f0, 0, 0x7e8)
  - read(0, src, 0x438)  → **溢出56字节**到 dst(rbp-0x7f0)头部
  - snprintf(dst, 0x7d0, "%s", src)  → format固定, dst与src重叠
  - printf("Your Input Is :%s", dst)
- `main (0xc3c)`: 菜单 scanf("%4s")->atoi->choice
  - choice==1: call b30
  - choice==2: malloc(0x100); read(0,chunk,0x100)[精确]; printf("...%s...",chunk)[格式固定]; free[无UAF]

### ★ 漏洞原语判定 (三重确认)
1. **栈溢出不可达**: read 0x438 溢出56字节仅污染 dst 头部, 距 canary 0x7b0 字节 → 无法覆盖 canary/saved RIP
2. **无格式串洞**: 所有 printf/snprintf format 均为编译期固定 "%s"
3. **choice2 无堆溢出**: malloc 0x100 与 read 0x100 精确; free 后无 UAF 引用
4. **唯一残留**: 输入无NUL时 snprintf/printf "%s" 越界读(dst/src重叠) → 仅能泄露栈/堆内存, 无控制流
→ PLT 无 system, **结论: 此 pwn 无法直接 RCE**

### 攻击套件
- `attack/pwn_exploit.py`: 自动连接→choice1/choice2 无NUL爆破 payload→捕获越界读泄露, 带自动重连(--loop N), 可批量对存活队跑
- 用法: `python3 pwn_exploit.py <host> <port> --loop N`

### 环境限制(实测)
- 当前沙箱: 9999/80 可建TCP但**代理不转发数据**(读不到banner), 22 SSH 时不可达 → 网络出口动态受限
- pwn 交互需在**本地可达网络**(如用户 kali) 运行 pwn_exploit.py 才有效

