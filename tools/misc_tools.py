#!/usr/bin/env python3
"""
Misc 工具集
子命令:
  wireshark  [attack|login|password|flag|sql|webshell|dns]  # 生成 Wireshark 过滤表达式
  steg-detect <file>       # 按文件类型跑隐写检测流程
  vol3     <mem.raw> [info|pslist|netscan|filescan|reg|strings]  # Volatility3 快捷命令
  decode   <string>        # 自动识别编码并解码
  portscan <target> [ports]  # 常用端口扫描
  proto-attack <target> <port>  # 常用未授权协议攻击
"""
import argparse, os, subprocess, sys, re, base64

def cmd_wireshark(args):
    templates = {
        "attack":  "tcp.flags.reset == 1 || http.response.code == 403 || tcp.len > 0 and data.data contains \"<?php\"",
        "login":   "http.request.method == \"POST\" && http.request.uri contains \"login\"",
        "password":"http.request.body matches \"(?i)(password|passwd|pwd|auth|token)=[^&]*\"",
        "flag":    "frame contains \"flag\" || data.data contains \"flag\" || http contains \"flag\" || dns.qry.name contains \"flag\"",
        "sql":     "data.data matches \"(?i)(union.*select|select.*from|drop.*table|sleep\\(|benchmark\\()\"",
        "webshell":"http.request.method == \"POST\" && http.request.body matches \"(@?eval|assert|system|exec|passthru|cmd|cmd=|c=)\"",
        "dns":     "dns.qry.name || dns.flags.response == 0",
        "file":    "http.content_type contains \"multipart/form-data\" || http.request.uri contains \"upload\"",
        "cookies": "http.cookie || http.set_cookie",
    }
    if args.type == "list":
        for k, v in templates.items(): print(f"{k:10s} : {v}")
        return
    if args.type in templates:
        print(templates[args.type])
    else:
        print(f"未找到类型: {args.type}. 可用: {list(templates.keys())}")

def cmd_steg_detect(args):
    fname = args.file
    print(f"[*] 隐写检测: {fname}")
    ftype = subprocess.check_output(["file", fname]).decode().lower()
    ext = fname.rsplit(".", 1)[-1].lower()

    steps = []
    if ext in ("png", "bmp"):
        steps += [
            ("binwalk -e", f"binwalk -e '{fname}' 2>&1 | head -30"),
            ("zsteg -a",  f"zsteg -a '{fname}' 2>&1 | head -50"),
            ("zsteg -e",  f"zsteg -e '{fname}'"),
            ("pngcheck -e",f"pngcheck -e '{fname}' 2>&1"),
        ]
    elif ext in ("jpg", "jpeg"):
        steps += [
            ("binwalk -e", f"binwalk -e '{fname}' 2>&1 | head -30"),
            ("steghide info", f"steghide info '{fname}' 2>&1"),
            ("strings",    f"strings '{fname}' | grep -iE 'flag|key|secret|password|ctf' | head -30"),
            ("exiftool",   f"exiftool '{fname}' 2>&1 | grep -v -i 'warning' | head -30"),
        ]
    elif ext in ("zip",):
        steps += [
            ("unzip -l",   f"unzip -l '{fname}'"),
            ("zip comment",f"unzip -z '{fname}' 2>&1"),
            ("binwalk -e", f"binwalk -e '{fname}' 2>&1 | head -30"),
        ]
    elif ext in ("pdf",):
        steps += [
            ("strings",    f"strings '{fname}' | grep -iE 'flag|key|secret' | head -30"),
            ("pdfinfo",    f"pdfinfo '{fname}' 2>&1"),
            ("pdftotext",  f"pdftotext '{fname}' - 2>/dev/null | grep -iE 'flag|key|secret'"),
        ]
    else:
        pid = os.getpid()
        steps += [
            ("binwalk -M", f"binwalk -M '{fname}' 2>&1 | head -50"),
            ("strings",    "strings '%s' | grep -iE 'flag|key|secret|password|ctf\\{' | head -50" % fname),
            ("foremost",   "foremost -i '%s' -o /tmp/steg_extract_%d 2>&1 | head -20; ls /tmp/steg_extract_%d 2>/dev/null" % (fname, pid, pid)),
        ]
    steps.append(("hexdump head", f"xxd '{fname}' | head -20"))
    steps.append(("exiftool",  f"exiftool '{fname}' 2>&1 | head -40"))

    for name, cmd in steps:
        print(f"\n[*] === {name} ===")
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=15).decode(errors="ignore")
            lines = [l for l in out.splitlines() if l.strip()]
            print("\n".join(lines[:40]))
            if len(lines) > 40: print(f"... 共 {len(lines)} 行, 已截断")
        except subprocess.CalledProcessError as e:
            print(f"  [!] 错误: {str(e)[:200]}")
        except subprocess.TimeoutExpired:
            print(f"  [!] 超时")

def cmd_vol3(args):
    cmds = {
        "info":     "windows.info",
        "pslist":   "windows.pslist",
        "netscan":  "windows.netscan",
        "filescan": "windows.filescan",
        "cmdscan":  "windows.cmdscan",
        "reg":      "windows.registry.hivescan; windows.registry.printkey --key \"Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\"",
        "strings":  "windows.strings -s | grep -iE 'flag|password|key|secret' | head -100",
    }
    mem = args.mem
    actions = args.actions.split(",")
    for act in actions:
        for subact in cmds.get(act, act).split(";"):
            subact = subact.strip()
            if not subact: continue
            cmd = f"vol -f {mem} {subact}"
            print(f"\n[*] === vol -f {mem} {subact} ===")
            os.system(f"{cmd} 2>&1 | head -80")

def cmd_decode(args):
    s = args.string.strip()
    print(f"[*] 原始: {s}")
    print()
    # Base64
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=]+", s) and len(s) % 4 == 0 and len(s) > 4:
            d = base64.b64decode(s).decode(errors="ignore")
            if d and all(32 <= ord(c) < 127 for c in d):
                print(f"Base64 → {d}")
    except Exception: pass
    # Hex
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 and len(s) > 2:
        try:
            d = bytes.fromhex(s).decode(errors="ignore")
            if d and all(32 <= ord(c) < 127 for c in d):
                print(f"Hex    → {d}")
        except Exception: pass
    # URL
    try:
        import urllib.parse as up
        d = up.unquote(s)
        if d != s: print(f"URL    → {d}")
    except Exception: pass
    # ROT13
    try:
        rot = s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz","NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        if any(w in rot.lower() for w in ["flag", "key", "pass", "secret"]):
            print(f"ROT13  → {rot}")
    except Exception: pass
    # ROT47
    try:
        r47 = ''.join(chr(33 + ((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in s)
        if any(w in r47.lower() for w in ["flag", "key", "pass", "secret"]):
            print(f"ROT47  → {r47}")
    except Exception: pass

def cmd_portscan(args):
    common_ports = "21,22,23,25,53,80,110,135,137,139,143,443,445,3306,3307,3389,5432,5900,5901,6379,8080,8443,9000,9090,9200,11211,27017,50070"
    ports = args.ports or common_ports
    target = args.target
    os.system(f"nmap -sV -Pn --open -p {ports} -T4 {target}")

def cmd_proto_attack(args):
    target, port = args.target, int(args.port)
    payloads = {
        6379: [("Redis", f"echo -e 'INFO\\nCONFIG GET dir\\nCONFIG GET dbfilename\\nKEYS *\\nGET flag' | nc -w 2 {target} {port}")],
        11211: [("Memcached", f"echo -e 'stats\\nstats slabs\\nstats items' | nc -w 2 {target} {port}")],
        27017: [("MongoDB", f"mongosh --quiet --host {target} --port {port} --eval 'db.adminCommand(\\\"listDatabases\\\")'")],
        50070: [("Hadoop HDFS", f"curl -s http://{target}:{port}/webhdfs/v1/?op=LISTSTATUS 2>&1 | head -50")],
        2375:  [("Docker API", f"curl -s http://{target}:{port}/v1.24/containers/json 2>&1 | head -40")],
        8080:  [("Jenkins/Manager", f"curl -s http://{target}:{port}/ 2>&1 | grep -iE 'jenkins|tomcat|manager|login' | head -10")],
        80:    [("HTTP", f"curl -s -I http://{target}:{port}/ 2>&1 | head -20")],
        9200:  [("Elasticsearch", f"curl -s http://{target}:{port}/_cat/indices?v 2>&1 | head -20")],
        445:   [("SMB", f"smbclient -L //{target} -N -I {target} 2>&1 | head -30")],
    }
    for name, cmd in payloads.get(port, [(f"Port {port}", f"nc -zv {target} {port} 2>&1")]):
        print(f"\n[*] === {name} on {target}:{port} ===")
        os.system(cmd)

def main():
    parser = argparse.ArgumentParser(description="AWD Misc 工具集")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("wireshark", help="生成 Wireshark 过滤表达式")
    p1.add_argument("type", help="类型 (list=列出全部, attack|login|password|flag|sql|webshell|dns|file|cookies)")
    p1.set_defaults(func=cmd_wireshark)

    p2 = sub.add_parser("steg-detect", help="隐写检测")
    p2.add_argument("file", help="待检测文件")
    p2.set_defaults(func=cmd_steg_detect)

    p3 = sub.add_parser("vol3", help="Volatility3 快捷命令")
    p3.add_argument("mem", help="内存镜像 mem.raw")
    p3.add_argument("actions", default="info,pslist,netscan", help="逗号分隔: info,pslist,netscan,filescan,cmdscan,reg,strings")
    p3.set_defaults(func=cmd_vol3)

    p4 = sub.add_parser("decode", help="自动识别编码解码")
    p4.add_argument("string", help="编码字符串")
    p4.set_defaults(func=cmd_decode)

    p5 = sub.add_parser("portscan", help="常用端口扫描")
    p5.add_argument("target", help="IP 或域名")
    p5.add_argument("ports", nargs="?", default=None, help="端口, 默认常用端口")
    p5.set_defaults(func=cmd_portscan)

    p6 = sub.add_parser("proto-attack", help="未授权协议攻击")
    p6.add_argument("target", help="目标 IP")
    p6.add_argument("port", type=int, help="端口")
    p6.set_defaults(func=cmd_proto_attack)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
