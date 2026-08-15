#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD 规则词表生成器 - 基于已知线索 + 队号/年份/常见生成模式.
用于 SSH 慢爆时优先命中"题目生成值"(如 Nsy@Awd#2026), 这些大字典覆盖不到.

用法: python3 gen_rule_dict.py [输出路径] [存活队号...]
默认: /tmp/rule_dict.txt ; 队号默认 31 72 91 98 119 189 192
"""
import sys

# 已知题目线索(用户提供)
KNOWN = ["Nsy@Awd#2026"]
TEAMS_DEFAULT = ["31", "72", "91", "98", "119", "189", "192"]


def build(out, teams):
    base = set()
    base.update(KNOWN)
    # --- 常见 AWD/CTF 口令 ---
    base.update([
        "admin", "password", "123456", "admin123", "password123", "12345678",
        "test", "123456789", "admin888", "qwer1234", "admin@123", "P@ssw0rd",
        "Awd2026", "awd2026", "bugku", "bugku2026", "pvp", "pvp2026",
        "root", "toor", "changeme", "admin@2026", "1234567890",
    ])
    # --- 组合: 前缀 + 队号 + 后缀 ---
    for t in teams:
        for pref in ["Nsy@Awd#", "Awd#", "Team", "team", "pw", "P@ss", "pass",
                      "root", "admin", "Bugku", "nsy"]:
            for sfx in ["2026", "2025", "Awd", "AWD", "#2026", "@2026", ""]:
                base.add(f"{pref}{t}{sfx}")
                base.add(f"{pref}{sfx}{t}")
        base.update({
            f"team{t}", f"Team{t}", f"Team{t}@Awd", f"Team{t}@Awd#2026",
            f"Nsy@Awd#{t}", f"{t}#2026",
        })

    with open(out, "w") as f:
        for x in sorted(base, key=str.lower):
            f.write(x + "\n")
    print(f"[+] 规则词表已生成: {out} = {len(base)} 条")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rule_dict.txt"
    teams = sys.argv[2:] if len(sys.argv) > 2 else TEAMS_DEFAULT
    build(out, teams)
