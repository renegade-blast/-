#!/usr/bin/env python3
"""
AWD IP 防火墙管理工具
- 白名单模式：只允许白名单 IP 访问，其余全部拦截
- 黑名单模式：明确封禁特定 IP
- 支持 CIDR（192.168.1.0/24）和单个 IP
- 3 层拦截：iptables（系统层）| .htaccess/nginx（Web层）| waf.php（应用层）

用法:
  python3 ip_firewall.py init --whitelist <whitelist.txt>          # 初始化目录结构
  python3 ip_firewall.py add white 192.168.1.100 "自己的攻击机"     # 添加白名单
  python3 ip_firewall.py add black 10.0.0.5 "扫描器 IP"            # 添加黑名单
  python3 ip_firewall.py rm white 192.168.1.100                     # 移除白名单
  python3 ip_firewall.py list                                       # 列出所有 IP
  python3 ip_firewall.py check 1.2.3.4                              # 检查 IP 是否被允许
  python3 ip_firewall.py generate iptables --chain AWD_FW           # 生成 iptables 规则
  python3 ip_firewall.py generate htaccess                          # 生成 .htaccess 规则
  python3 ip_firewall.py generate nginx                             # 生成 nginx 片段
  python3 ip_firewall.py generate waf                               # 生成 PHP 数组 (供 waf.php 包含)
  python3 ip_firewall.py apply iptables                             # 直接应用 iptables 规则到本机
  python3 ip_firewall.py auto-ban 10.0.0.9 "扫描: 路径爆破"         # 自动封禁 + 写入日志
"""
import argparse
import ipaddress
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime

# 存储结构: JSON
STORE_DIR = Path(os.environ.get("AWD_IPFW_DIR", "/tmp/awd_ipfw"))
STORE_FILE = STORE_DIR / "ip_rules.json"
BAN_LOG = STORE_DIR / "ban.log"
AUDIT_LOG = STORE_DIR / "audit.log"

DEFAULT_RULES = {
    "whitelist": [
        # {"ip": "127.0.0.1", "note": "localhost", "time": "..."}
        # {"ip": "192.168.1.0/24", "note": "内网", "time": "..."}
    ],
    "blacklist": [],
    "meta": {
        "default_policy": "deny",  # deny = 白名单模式(默认) | allow = 黑名单模式
        "created": None,
        "updated": None,
    }
}


def ensure_store():
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    if not STORE_FILE.exists():
        DEFAULT_RULES["meta"]["created"] = _now()
        DEFAULT_RULES["meta"]["updated"] = _now()
        _save(DEFAULT_RULES)
    return _load()


def _load():
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data):
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_ip(s):
    """允许单个 IP 或 CIDR，返回 ipaddress 对象"""
    if "/" in s:
        return ipaddress.ip_network(s, strict=False)
    return ipaddress.ip_address(s)


def _in_list(ip_obj, entry_list):
    for e in entry_list:
        try:
            rule = _parse_ip(e["ip"])
        except ValueError:
            continue
        if isinstance(rule, ipaddress._BaseNetwork):
            if isinstance(ip_obj, ipaddress._BaseNetwork):
                if ip_obj.subnet_of(rule):
                    return e
            else:
                if ip_obj in rule:
                    return e
        else:
            if isinstance(ip_obj, ipaddress._BaseNetwork):
                if rule in ip_obj:
                    return e
            else:
                if ip_obj == rule:
                    return e
    return None


def cmd_init(args):
    data = ensure_store()
    # 从文件批量导入白名单
    if args.whitelist and os.path.exists(args.whitelist):
        added = 0
        for line in open(args.whitelist, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            ip = parts[0]
            note = parts[1] if len(parts) > 1 else "批量导入"
            added += cmd_add_internal(data, "white", ip, note)
        data["meta"]["updated"] = _now()
        _save(data)
        print(f"✅ 初始化完成，新增 {added} 条白名单规则")
    else:
        print("✅ 初始化完成（未导入批量白名单）")
    print(f"   规则文件: {STORE_FILE}")
    print(f"   默认策略: {data['meta']['default_policy']} (deny=除白名单外全拦)")


def cmd_add_internal(data, kind, ip, note):
    entry = {"ip": ip, "note": note or "", "time": _now()}
    # 校验格式
    try:
        _parse_ip(ip)
    except ValueError as e:
        print(f"[!] IP 格式错误: {ip} -> {e}")
        return 0
    key = "whitelist" if kind == "white" else "blacklist"
    # 去重
    if any(x["ip"] == ip for x in data[key]):
        print(f"[-] {ip} 已在{key}中，跳过")
        return 0
    data[key].append(entry)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] ADD {kind.upper()} {ip}  note={note}\n")
    print(f"[+] {'白' if kind=='white' else '黑'}名单: {ip} ({note})")
    return 1


def cmd_add(args):
    data = ensure_store()
    n = cmd_add_internal(data, args.kind, args.ip, args.note)
    if n:
        data["meta"]["updated"] = _now()
        _save(data)


def cmd_rm(args):
    data = ensure_store()
    key = "whitelist" if args.kind == "white" else "blacklist"
    before = len(data[key])
    data[key] = [e for e in data[key] if e["ip"] != args.ip]
    if len(data[key]) == before:
        print(f"[!] {args.ip} 不在{key}中")
        return
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] REMOVE {args.kind.upper()} {args.ip}\n")
    data["meta"]["updated"] = _now()
    _save(data)
    print(f"[-] 移除: {args.ip}")


def cmd_list(args):
    data = ensure_store()
    policy = data["meta"]["default_policy"]
    print(f"默认策略: {'白名单模式(除以下外全部拦截)' if policy=='deny' else '黑名单模式(仅拦截以下)'}")
    print(f"创建时间: {data['meta']['created']}    最近更新: {data['meta']['updated']}")
    print()
    for key, title in [("whitelist", "✅ 白名单 IP"), ("blacklist", "❌ 黑名单 IP")]:
        print(f"{title} ({len(data[key])})")
        print("-" * 70)
        for e in data[key]:
            print(f"  {e['ip']:<22}  {e.get('time',''):<20}  {e.get('note','')}")
        print()


def cmd_check(args):
    data = ensure_store()
    ip = ipaddress.ip_address(args.ip)
    policy = data["meta"]["default_policy"]

    w = _in_list(ip, data["whitelist"])
    b = _in_list(ip, data["blacklist"])

    decision = "UNKNOWN"
    reason = ""
    if b:
        decision = "BLOCK ❌"
        reason = f"命中黑名单 (note={b.get('note')}, 时间={b.get('time')})"
    elif w:
        decision = "ALLOW ✅"
        reason = f"命中白名单 (note={w.get('note')}, 时间={w.get('time')})"
    else:
        if policy == "deny":
            decision = "BLOCK ❌"
            reason = "默认策略 deny: 不在白名单 → 拦截"
        else:
            decision = "ALLOW ⚠️"
            reason = "默认策略 allow: 不在黑名单 → 放行"

    print(f"IP: {args.ip}")
    print(f"结果: {decision}")
    print(f"原因: {reason}")
    return 0 if decision.startswith("ALLOW") else 1


def gen_list_flat(entry_list):
    """把 CIDR + IP 混合展开为: 单个IP列表 + CIDR列表"""
    ips = []
    nets = []
    for e in entry_list:
        try:
            x = _parse_ip(e["ip"])
        except ValueError:
            continue
        if isinstance(x, ipaddress._BaseNetwork):
            nets.append(x)
        else:
            ips.append(x)
    return ips, nets


def cmd_generate(args):
    data = ensure_store()
    fmt = args.format
    policy = data["meta"]["default_policy"]
    w_ips, w_nets = gen_list_flat(data["whitelist"])
    b_ips, b_nets = gen_list_flat(data["blacklist"])

    out = []
    if fmt == "iptables":
        chain = args.chain or "AWD_FW"
        out.append("# ===== AWD IP 防火墙: iptables 规则 (默认 deny) =====")
        out.append(f"# 生成时间: {_now()}")
        out.append(f"# 白名单: {len(data['whitelist'])}  黑名单: {len(data['blacklist'])}  默认策略: {policy}")
        out.append(f"iptables -N {chain} 2>/dev/null || true")
        out.append(f"iptables -F {chain}")
        # 黑名单优先，直接 DROP
        for ip in b_ips:
            out.append(f"iptables -A {chain} -s {ip} -j DROP -m comment --comment 'awd:blacklist'")
        for net in b_nets:
            out.append(f"iptables -A {chain} -s {net} -j DROP -m comment --comment 'awd:blacklist'")
        # 白名单允许
        for ip in w_ips:
            out.append(f"iptables -A {chain} -s {ip} -j ACCEPT -m comment --comment 'awd:whitelist'")
        for net in w_nets:
            out.append(f"iptables -A {chain} -s {net} -j ACCEPT -m comment --comment 'awd:whitelist'")
        # 回环允许
        out.append(f"iptables -A {chain} -s 127.0.0.1 -j ACCEPT -m comment --comment 'awd:loopback'")
        # 默认策略：剩下的全部 REJECT (不DROP防止ICMP调试，可改DROP)
        if policy == "deny":
            out.append(f"iptables -A {chain} -j REJECT --reject-with icmp-host-prohibited -m comment --comment 'awd:default_deny'")
        else:
            out.append(f"iptables -A {chain} -j ACCEPT")
        # 挂到 INPUT/FORWARD
        out.append(f"iptables -I INPUT -j {chain}")
        out.append(f"iptables -I FORWARD -j {chain}")
        out.append("# 撤销命令: iptables -D INPUT -j {c}; iptables -D FORWARD -j {c}; iptables -F {c}; iptables -X {c}".format(c=chain))

    elif fmt == "htaccess":
        out.append("## ===== AWD IP 防火墙: Apache .htaccess ===== ")
        out.append(f"## 默认策略: {'Deny,Allow (白名单模式，非白403)' if policy=='deny' else 'Allow,Deny'}")
        if policy == "deny":
            # Order Deny,Allow: 先评估所有 Deny，再评估 Allow。默认 deny: 任何没被 allow 的都 deny
            out.append("Order Deny,Allow")
            out.append("Deny from all")
            for ip in w_ips:
                out.append(f"Allow from {ip}")
            for net in w_nets:
                out.append(f"Allow from {net}")
        else:
            out.append("Order Allow,Deny")
            out.append("Allow from all")
            for ip in b_ips:
                out.append(f"Deny from {ip}")
            for net in b_nets:
                out.append(f"Deny from {net}")

    elif fmt == "nginx":
        out.append("## ===== AWD IP 防火墙: nginx http/server/location block 可粘贴 ===== ")
        out.append(f"## 默认策略: {'deny all (白名单)' if policy=='deny' else 'allow all (黑名单)'}")
        if policy == "deny":
            for ip in w_ips:
                out.append(f"allow {ip};")
            for net in w_nets:
                out.append(f"allow {net};")
            out.append("deny all;")
        else:
            for ip in b_ips:
                out.append(f"deny {ip};")
            for net in b_nets:
                out.append(f"deny {net};")
            out.append("allow all;")

    elif fmt == "waf":
        # 生成 PHP 数组给 waf.php 包含
        out.append("<?php ")
        out.append("// AWD IP 防火墙: waf.php 包含使用")
        out.append(f"// 默认策略: {policy}")
        out.append(f"define('AWD_WAF_DEFAULT_POLICY', '{policy}');")
        out.append("$GLOBALS['AWD_IPFW_WHITELIST'] = [")
        for e in data["whitelist"]:
            out.append(f"  '{e['ip']}',    // {e.get('note','')}")
        out.append("];")
        out.append("$GLOBALS['AWD_IPFW_BLACKLIST'] = [")
        for e in data["blacklist"]:
            out.append(f"  '{e['ip']}',    // {e.get('note','')}")
        out.append("];")
        out.append("?>")

    result = "\n".join(out) + "\n"
    if args.out:
        Path(args.out).write_text(result, encoding="utf-8")
        print(f"✅ 已写入 {args.out} ({len(out)-1} 行)")
    else:
        sys.stdout.write(result)


def cmd_apply_iptables(args):
    """把 generate iptables 的结果直接用 bash 执行（需要 root）"""
    import subprocess
    import tempfile
    data = ensure_store()
    # 先生成到临时变量
    class FakeArgs:
        format = "iptables"
        chain = args.chain
        out = None
    # 借用 generate 的 stdout
    from io import StringIO
    old = sys.stdout
    sys.stdout = StringIO()
    try:
        cmd_generate(FakeArgs())
        script = sys.stdout.getvalue()
    finally:
        sys.stdout = old

    if args.dry:
        print(script)
        return
    # 执行
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    print(f"exit={r.returncode}")
    if r.stdout:
        print("stdout:", r.stdout[:500])
    if r.stderr:
        print("stderr:", r.stderr[:500])
    if r.returncode == 0:
        print("✅ iptables 规则已应用")
        print("   查看: iptables -L AWD_FW -n -v")
    else:
        print("⚠️  执行失败 (需要 root 权限? 用 sudo 重试)")


def cmd_auto_ban(args):
    data = ensure_store()
    # 加入黑名单
    cmd_add_internal(data, "black", args.ip, args.reason or "auto-ban")
    data["meta"]["updated"] = _now()
    _save(data)
    # 写入 ban log
    with open(BAN_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] BAN {args.ip}  reason={args.reason or 'auto-ban'}\n")
    # 尝试用 iptables 立即封禁（如果权限允许，失败也不中断）
    try:
        import subprocess
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", args.ip, "-j", "DROP", "-m", "comment", "--comment", "awd:autoban"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass
    print(f"🚫 已封禁 IP: {args.ip}  ({args.reason})")


def main():
    p = argparse.ArgumentParser(description="AWD IP 防火墙 / 白名单管理")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="初始化存储结构，支持批量导入白名单")
    pi.add_argument("--whitelist", help="白名单文本文件 (IP 或 CIDR，空格后可加注释)")
    pi.set_defaults(func=cmd_init)

    pa = sub.add_parser("add", help="add white|black <IP/CIDR> [note]")
    pa.add_argument("kind", choices=["white", "black"])
    pa.add_argument("ip")
    pa.add_argument("note", nargs="?", default="")
    pa.set_defaults(func=cmd_add)

    pr = sub.add_parser("rm", help="rm white|black <IP/CIDR>")
    pr.add_argument("kind", choices=["white", "black"])
    pr.add_argument("ip")
    pr.set_defaults(func=cmd_rm)

    pl = sub.add_parser("list", help="列出所有 IP")
    pl.set_defaults(func=cmd_list)

    pc = sub.add_parser("check", help="check <ip>  判断访问决策")
    pc.add_argument("ip")
    pc.set_defaults(func=cmd_check)

    pg = sub.add_parser("generate", help="generate iptables|htaccess|nginx|waf [--out file]")
    pg.add_argument("format", choices=["iptables", "htaccess", "nginx", "waf"])
    pg.add_argument("--chain", default="AWD_FW", help="iptables 自定义链名")
    pg.add_argument("--out", help="输出到文件 (默认 stdout)")
    pg.set_defaults(func=cmd_generate)

    papp = sub.add_parser("apply", help="直接应用规则到本机系统 (支持 iptables)")
    papp_sub = papp.add_subparsers(dest="apply_target", required=True)
    papp_ipt = papp_sub.add_parser("iptables")
    papp_ipt.add_argument("--chain", default="AWD_FW")
    papp_ipt.add_argument("--dry", action="store_true", help="仅打印不执行")
    papp_ipt.set_defaults(func=cmd_apply_iptables)

    pb = sub.add_parser("auto-ban", help="auto-ban <IP> [reason]  一键拉黑 + 写日志 + iptables 立即封")
    pb.add_argument("ip")
    pb.add_argument("reason", nargs="?", default="")
    pb.set_defaults(func=cmd_auto_ban)

    args = p.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
