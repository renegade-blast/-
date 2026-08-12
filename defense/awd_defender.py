#!/usr/bin/env python3
"""
AWD 防御脚本模板 - 服务器加固与监控
用途: 自动加固服务器, 监控文件和进程, 恢复被篡改的服务
"""

import os
import subprocess
import time
import re
import hashlib
import threading
from datetime import datetime


class AWDDefender:
    def __init__(self):
        self.watch_files = {}
        self.alerts = []
        self.running = True

    def harden_ssh(self):
        """加固 SSH 配置"""
        print("[*] 加固 SSH 配置...")
        ssh_config = "/etc/ssh/sshd_config"
        if not os.path.exists(ssh_config):
            return

        try:
            with open(ssh_config, 'r') as f:
                config = f.read()

            harden_rules = [
                ('PermitRootLogin', 'no'),
                ('PasswordAuthentication', 'no'),
                ('MaxAuthTries', '3'),
                ('LoginGraceTime', '30'),
                ('AllowTcpForwarding', 'no'),
            ]

            for key, value in harden_rules:
                pattern = rf'^{key}\s+.*'
                if re.search(pattern, config, re.MULTILINE):
                    config = re.sub(pattern, f'{key} {value}', config, flags=re.MULTILINE)
                else:
                    config += f'\n{key} {value}\n'

            with open(ssh_config, 'w') as f:
                f.write(config)

            subprocess.run(['service', 'ssh', 'restart'], capture_output=True)
            print("[+] SSH 加固完成")
        except Exception as e:
            print(f"[-] SSH 加固失败: {e}")

    def harden_php(self, php_path=None):
        """加固 PHP 配置"""
        print("[*] 加固 PHP 配置...")
        php_ini_paths = [
            '/etc/php/7.4/apache2/php.ini',
            '/etc/php/8.0/apache2/php.ini',
            '/etc/php/7.4/cli/php.ini',
        ]

        harden_rules = {
            'disable_functions': 'system,exec,shell_exec,passthru,proc_open,pcntl_exec',
            'allow_url_include': 'Off',
            'open_basedir': '/var/www/html:/tmp',
            'expose_php': 'Off',
            'display_errors': 'Off',
            'log_errors': 'On',
            'disable_classes': '',
        }

        for php_path in php_ini_paths:
            if os.path.exists(php_path):
                try:
                    with open(php_path, 'r') as f:
                        config = f.read()

                    for key, value in harden_rules.items():
                        pattern = rf'^{key}\s*=\s*.*'
                        if re.search(pattern, config, re.MULTILINE):
                            config = re.sub(
                                pattern, f'{key} = {value}', config, flags=re.MULTILINE
                            )

                    with open(php_path, 'w') as f:
                        f.write(config)
                    print(f"[+] {php_path} 加固完成")
                except Exception as e:
                    print(f"[-] {php_path} 加固失败: {e}")

    def harden_mysql(self):
        """加固 MySQL 配置"""
        print("[*] 加固 MySQL 配置...")
        harden_sqls = [
            "DELETE FROM mysql.user WHERE User='';",
            "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1');",
            "DROP DATABASE IF EXISTS test;",
            "DELETE FROM mysql.db WHERE Db='test';",
            "FLUSH PRIVILEGES;",
        ]

        for sql in harden_sqls:
            try:
                subprocess.run(
                    ['mysql', '-u', 'root', '-e', sql],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        print("[+] MySQL 加固完成")

    def block_suspicious_ips(self, ip_list=None):
        """封禁可疑 IP"""
        print("[*] 封禁可疑 IP...")
        if ip_list is None:
            ip_list = self._get_suspicious_ips()

        for ip in ip_list:
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            print(f"[+] 已封禁: {ip}")

    def _get_suspicious_ips(self):
        """从日志中提取可疑 IP"""
        suspicious = set()
        log_files = [
            '/var/log/auth.log',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    result = subprocess.run(
                        ['grep', '-i', 'fail', log_file],
                        capture_output=True, text=True, timeout=5
                    )
                    for match in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', result.stdout):
                        suspicious.add(match.group(1))
                except Exception:
                    pass

        return list(suspicious)[:100]

    def setup_file_monitor(self, paths_to_watch):
        """设置文件完整性监控"""
        print("[*] 启动文件完整性监控...")
        for path in paths_to_watch:
            if os.path.exists(path):
                self.watch_files[path] = hashlib.md5(
                    open(path, 'rb').read()
                ).hexdigest()
                print(f"  [监控] {path}")

    def check_file_integrity(self):
        """检查文件完整性"""
        for path, original_hash in self.watch_files.items():
            if os.path.exists(path):
                current_hash = hashlib.md5(
                    open(path, 'rb').read()
                ).hexdigest()
                if current_hash != original_hash:
                    alert = f"[!] 文件被篡改: {path} @ {datetime.now()}"
                    self.alerts.append(alert)
                    print(alert)
                    self._alert_response(path)

    def _alert_response(self, path):
        """检测到篡改后的响应"""
        # 可以在此添加自动恢复逻辑
        pass

    def kill_suspicious_processes(self):
        """查杀可疑进程"""
        print("[*] 查杀可疑进程...")
        suspicious_names = ['cryptonight', 'xmrig', 'minerd', 'kinsing', 'kdevtmpfsi']

        for name in suspicious_names:
            result = subprocess.run(
                ['pgrep', '-f', name],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                for pid in result.stdout.strip().split('\n'):
                    subprocess.run(['kill', '-9', pid], capture_output=True)
                    print(f"[+] 已查杀进程 {pid} ({name})")

    def start_monitoring(self, interval=30):
        """启动持续监控"""
        print(f"[*] 启动持续监控, 间隔 {interval}s")
        print("[*] 按 Ctrl+C 退出")

        def monitor_loop():
            while self.running:
                try:
                    self.check_file_integrity()
                    self.kill_suspicious_processes()
                    time.sleep(interval)
                except KeyboardInterrupt:
                    self.running = False
                    print("\n[*] 监控已停止")

        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        return thread


def main():
    defender = AWDDefender()

    # 1. 基础加固
    defender.harden_ssh()
    defender.harden_php()
    defender.harden_mysql()
    defender.block_suspicious_ips()

    # 2. 文件监控
    critical_files = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/crontab',
        '/var/www/html/config.php',
    ]
    defender.setup_file_monitor(critical_files)

    # 3. 启动监控
    monitor_thread = defender.start_monitoring(interval=30)

    # 保持运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        defender.running = False
        print("\n[*] 防御系统已停止")


if __name__ == '__main__':
    main()
