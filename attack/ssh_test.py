#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 弱口令测试 (paramiko 单线程串行, 稳定不崩)"""
import sys, paramiko

def test(host, user, passwd):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(host, port=22, username=user, password=passwd, timeout=6,
                   banner_timeout=6, auth_timeout=6, look_for_keys=False, allow_agent=False)
        return "SUCCESS"
    except paramiko.AuthenticationException:
        return "FAIL"
    except Exception:
        return "NETERR"
    finally:
        try: cl.close()
        except Exception: pass

def main():
    host = sys.argv[1]
    user = sys.argv[2]
    wordlist = sys.argv[3]
    found = False
    with open(wordlist, encoding='utf-8', errors='replace') as f:
        for line in f:
            p = line.strip()
            if not p or p.startswith('#'):
                continue
            r = test(host, user, p)
            if r == "SUCCESS":
                print(f"[*] CREDENTIAL FOUND: {user} / {p}")
                with open('/tmp/ssh_hit.txt', 'a') as o:
                    o.write(f"{host} {user} {p}\n")
                found = True
                return
            elif r == "NETERR":
                print(f"[!] net err at {p}", flush=True)
    if not found:
        print(f"[done] no hit for {user} on {host}")

if __name__ == "__main__":
    main()
