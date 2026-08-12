#!/usr/bin/env python3
"""
AWD 防御 - 日志监控与源码备份脚本
用途: 实时日志监控, 异常行为告警, 源码自动备份
"""

import os
import re
import sys
import json
import hashlib
import time
import shutil
import threading
from datetime import datetime
from pathlib import Path


class LogMonitor:
    def __init__(self, log_dirs=None, watch_files=None, backup_dir='/tmp/awd_backups'):
        self.log_dirs = log_dirs or ['/var/log', '/var/log/apache2', '/var/log/nginx', '/var/log/mysql']
        self.watch_files = watch_files or ['/var/log/auth.log', '/var/log/secure',
                                           '/var/log/apache2/access.log', '/var/log/apache2/error.log',
                                           '/var/log/nginx/access.log', '/var/log/nginx/error.log']
        self.backup_dir = backup_dir
        self.alerts = []
        self.log_entries = []
        self.running = True
        self.file_baselines = {}

    # ========= 1. 日志异常检测 =========
    def analyze_auth_logs(self):
        """分析认证日志"""
        print("\n[*] 分析认证日志")

        alert_patterns = [
            (r'Failed password.*from\s+(\S+)', 'ssh_brute_force', 'high'),
            (r'Accepted password.*from\s+(\S+)', 'ssh_login', 'info'),
            (r'Accepted publickey.*from\s+(\S+)', 'ssh_key_login', 'info'),
            (r'invalid user.*from\s+(\S+)', 'suspicious_user', 'medium'),
            (r'authentication failure', 'auth_failure', 'medium'),
            (r'maximum authentication attempts exceeded', 'ssh_max_auth', 'high'),
            (r'sudo.*COMMAND=', 'sudo_usage', 'info'),
            (r'su\(pam_unix\).*session opened', 'su_success', 'info'),
            (r'su\(pam_unix\).*authentication failure', 'su_fail', 'high'),
        ]

        auth_logs = ['/var/log/auth.log', '/var/log/secure']
        alerts_found = []

        for log_file in auth_logs:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', errors='ignore') as f:
                        lines = f.readlines()[-1000:]

                    for line in lines:
                        for pattern, alert_type, severity in alert_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                ip_match = re.search(r'from\s+(\S+)', line)
                                alert = {
                                    'type': alert_type,
                                    'file': log_file,
                                    'severity': severity,
                                    'ip': ip_match.group(1) if ip_match else 'N/A',
                                    'log': line.strip()[:200],
                                    'time': datetime.now().isoformat(),
                                }
                                alerts_found.append(alert)
                                self.alerts.append(alert)
                                break
                except Exception:
                    pass

        # 暴力破解聚合
        ip_counts = {}
        for a in alerts_found:
            if a['type'] == 'ssh_brute_force':
                ip_counts[a['ip']] = ip_counts.get(a['ip'], 0) + 1

        for ip, count in ip_counts.items():
            if count >= 5:
                print(f"  [!!!] SSH 暴力破解: {ip} ({count} 次尝试)")
                try:
                    import subprocess
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                                   capture_output=True, timeout=3)
                    print(f"    [+] 已封禁 IP {ip}")
                except Exception:
                    pass

        if alerts_found:
            print(f"  [+] 发现 {len(alerts_found)} 条认证事件")
        return alerts_found

    def analyze_web_logs(self):
        """分析 Web 日志 - 检测 Web 攻击"""
        print("\n[*] 分析 Web 日志")

        attack_patterns = {
            'sql_injection': [
                r"(UNION|SELECT|INSERT|UPDATE|DELETE).*FROM",
                r"('|%27).*(OR|AND).*('|%27)",
                r"CONVERT\s*\(",
                r"CHAR\s*\(\s*\d+",
                r"0x[0-9a-fA-F]{4,}",
                r"SLEEP\s*\(\s*\d+",
                r"BENCHMARK\s*\(",
                r"extractvalue\s*\(",
                r"updatexml\s*\(",
                r"information_schema",
            ],
            'xss': [
                r"<script[^>]*>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
                r"onmouseover\s*=",
                r"<iframe",
                r"<svg[^>]*on",
                r"alert\s*\(",
                r"document\.cookie",
            ],
            'command_injection': [
                r";\s*(id|ls|cat|uname|whoami)",
                r"\|\s*(id|ls|cat|uname)",
                r"\$\(\s*(id|ls|cat)",
                r"`(id|ls|cat|uname)`",
                r"/dev/tcp/",
                r"bash\s+-i",
                r"shell_exec",
                r"system\s*\(",
            ],
            'file_inclusion': [
                r"php://filter",
                r"php://input",
                r"/etc/passwd",
                r"/etc/shadow",
                r"/proc/self/",
                r"file:///",
                r"data://",
                r"expect://",
            ],
            'file_upload': [
                r"Content-Type.*(php|phtml|py|sh)",
                r"\.php\b.*(upload|file)",
                r"multipart/form-data",
                r"%00",
                r"\.htaccess",
                r"\.user\.ini",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e/",
                r"\.\.%2f",
                r"%c0%ae",
            ],
            'deserialization': [
                r"O:\d+:",
                r"a:\d+:\{",
                r'"@type"',
                r"rce",
                r"poc",
                r"cpos\x",
            ],
        }

        web_logs = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
        ]

        attack_alerts = []
        for log_file in web_logs:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    lines = f.readlines()[-5000:]

                for line in lines:
                    for attack_type, patterns in attack_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                alert = {
                                    'type': attack_type,
                                    'log_file': log_file,
                                    'severity': 'critical',
                                    'log': line.strip()[:200],
                                    'time': datetime.now().isoformat(),
                                }
                                attack_alerts.append(alert)
                                self.alerts.append(alert)
                                break
            except Exception:
                pass

        # 去重 (按类型)
        unique_types = set(a['type'] for a in attack_alerts)
        for t in unique_types:
            count = sum(1 for a in attack_alerts if a['type'] == t)
            print(f"  [!] {t}: {count} 次")

        return attack_alerts

    def analyze_system_logs(self):
        """分析系统日志"""
        print("\n[*] 分析系统日志")

        suspicious_patterns = [
            (r'miner|xmrig|cryptonight', 'cryptocurrency_miner', 'critical'),
            (r'kinsing|kdevtmpfsi', 'linux_miner', 'critical'),
            (r'wget.*\.(sh|py|pl)', 'suspicious_download', 'high'),
            (r'curl.*\.(sh|py|pl)', 'suspicious_download', 'high'),
            (r'chmod\s*\+[xs]', 'chmod_suid', 'high'),
            (r'chown.*\d{3}:\d{3}', 'chown_suspicious', 'medium'),
            (r'mount.*noexec', 'mount_change', 'medium'),
            (r'iptables.*(-D|-F|-X)', 'firewall_removed', 'critical'),
            (r'/tmp/.*\.(php|sh|py|pl)', 'temp_malicious', 'high'),
            (r'/dev/shm/', 'shared_mem_usage', 'medium'),
            (r'crontab.*-r', 'cron_removed', 'high'),
            (r'pam_unix.*session closed', 'user_logout', 'info'),
        ]

        sys_logs = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/kern.log',
        ]

        sys_alerts = []
        for log_file in sys_logs:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    lines = f.readlines()[-2000:]

                for line in lines:
                    for pattern, alert_type, severity in suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            alert = {
                                'type': alert_type,
                                'file': log_file,
                                'severity': severity,
                                'log': line.strip()[:200],
                                'time': datetime.now().isoformat(),
                            }
                            sys_alerts.append(alert)
                            self.alerts.append(alert)
                            break
            except Exception:
                pass

        if sys_alerts:
            for a in sys_alerts[:10]:
                print(f"  [{a['severity']}] {a['type']}: {a['log'][:80]}")
        return sys_alerts

    # ========= 2. 实时监控 =========
    def start_realtime_monitor(self, interval=10):
        """启动实时日志监控"""
        print(f"\n[*] 启动实时监控 (间隔 {interval}s)")
        print(f"[*] 按 Ctrl+C 停止")

        def monitor_loop():
            while self.running:
                try:
                    self.analyze_auth_logs()
                    self.analyze_web_logs()
                    self.analyze_system_logs()
                    time.sleep(interval)
                except KeyboardInterrupt:
                    self.running = False
                    print("\n[*] 监控已停止")
                except Exception as e:
                    pass

        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        return thread

    # ========= 3. 源码备份 =========
    def backup_source(self, source_dir='/var/www/html'):
        """备份源码"""
        print(f"\n[*] 源码备份: {source_dir}")

        if not os.path.exists(source_dir):
            print(f"  [!] {source_dir} 不存在")
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, backup_name)

        # 创建备份目录
        os.makedirs(backup_path, exist_ok=True)

        # 复制源码
        try:
            for item in os.listdir(source_dir):
                src = os.path.join(source_dir, item)
                dst = os.path.join(backup_path, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                elif os.path.isdir(src):
                    if item not in ['.git', 'node_modules']:
                        shutil.copytree(src, dst, symlinks=True)

            # 生成文件清单
            file_list = []
            for root, dirs, files in os.walk(backup_path):
                for f in files:
                    filepath = os.path.join(root, f)
                    relpath = os.path.relpath(filepath, backup_path)
                    file_hash = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
                    file_list.append({
                        'path': relpath,
                        'size': os.path.getsize(filepath),
                        'sha256': file_hash,
                    })

            manifest = {
                'backup_time': datetime.now().isoformat(),
                'source_dir': source_dir,
                'file_count': len(file_list),
                'files': file_list,
            }

            with open(os.path.join(backup_path, 'manifest.json'), 'w') as f:
                json.dump(manifest, f, indent=2)

            # 创建压缩包
            archive_base = os.path.join(self.backup_dir, backup_name)
            shutil.make_archive(archive_base, 'tar', backup_path)

            # 清理临时目录
            shutil.rmtree(backup_path)

            archive_path = archive_base + '.tar'
            size_mb = os.path.getsize(archive_path) / (1024*1024)

            print(f"  [+] 备份完成: {archive_path}")
            print(f"      文件数: {len(file_list)}")
            print(f"      大小: {size_mb:.2f} MB")

            return {
                'path': archive_path,
                'files': len(file_list),
                'size': size_mb,
                'manifest': manifest,
            }

        except Exception as e:
            print(f"  [-] 备份失败: {e}")
            return None

    # ========= 4. 文件完整性监控 =========
    def monitor_file_integrity(self, paths=None, interval=30):
        """监控关键文件完整性"""
        print(f"\n[*] 文件完整性监控")

        if paths is None:
            paths = [
                '/etc/passwd', '/etc/shadow', '/etc/crontab',
                '/etc/ssh/sshd_config', '/etc/hosts',
                '/etc/sudoers', '/etc/fstab',
            ]

        # 建立基线
        baselines = {}
        for path in paths:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    baselines[path] = hashlib.sha256(f.read()).hexdigest()
                print(f"  [*] 基线: {path}")

        # 监控循环
        def integrity_loop():
            while self.running:
                for path, expected_hash in baselines.items():
                    if not os.path.exists(path):
                        print(f"  [!!!] 文件被删除: {path}")
                        alert = {'type': 'file_deleted', 'path': path, 'severity': 'critical'}
                        self.alerts.append(alert)
                        continue

                    with open(path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()

                    if current_hash != expected_hash:
                        print(f"  [!!!] 文件被篡改: {path}")
                        print(f"      原: {expected_hash[:16]}...")
                        print(f"      现: {current_hash[:16]}...")
                        alert = {
                            'type': 'file_modified',
                            'path': path,
                            'original_hash': expected_hash,
                            'current_hash': current_hash,
                            'severity': 'critical',
                        }
                        self.alerts.append(alert)

                        # 尝试恢复
                        try:
                            with open(path, 'wb') as f:
                                pass  # 需要原始备份才能恢复
                        except Exception:
                            pass

                time.sleep(interval)

        thread = threading.Thread(target=integrity_loop, daemon=True)
        thread.start()
        return thread

    # ========= 5. 日志清理与归档 =========
    def cleanup_old_logs(self, max_age_days=30):
        """清理旧日志"""
        print(f"\n[*] 清理超过 {max_age_days} 天的日志")

        import datetime as dt
        cutoff = dt.datetime.now() - dt.timedelta(days=max_age_days)

        cleaned = 0
        for log_dir in ['/var/log']:
            if os.path.exists(log_dir):
                for root, dirs, files in os.walk(log_dir):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            mtime = dt.datetime.fromtimestamp(os.path.getmtime(filepath))
                            if mtime < cutoff:
                                # 压缩归档
                                if not filepath.endswith('.gz'):
                                    import gzip
                                    with open(filepath, 'rb') as f_in:
                                        with gzip.open(filepath + '.gz', 'wb') as f_out:
                                            f_out.write(f_in.read())
                                    os.remove(filepath)
                                    cleaned += 1
                        except Exception:
                            pass

        print(f"  [+] 已清理 {cleaned} 个旧日志文件")
        return cleaned

    # ========= 6. 告警输出 =========
    def output_alerts(self, output_file='awd_alerts.json'):
        """输出所有告警"""
        if not self.alerts:
            print("\n[+] 暂无告警")
            return

        print(f"\n{'='*60}")
        print(f"  AWD 告警汇总")
        print(f"{'='*60}")
        print(f"  总数: {len(self.alerts)}")

        # 按严重级别分组
        by_severity = {}
        for alert in self.alerts:
            sev = alert.get('severity', 'low')
            by_severity.setdefault(sev, []).append(alert)

        for sev, alerts in by_severity.items():
            print(f"\n  [{sev}] ({len(alerts)} 条)")
            for a in alerts[:10]:
                print(f"    - {a.get('type','')}: {a.get('log', a.get('message', ''))[:80]}")
            if len(alerts) > 10:
                print(f"    ... 还有 {len(alerts)-10} 条")

        # 保存到文件
        with open(output_file, 'w') as f:
            json.dump({
                'total': len(self.alerts),
                'by_severity': {k: len(v) for k, v in by_severity.items()},
                'alerts': self.alerts,
                'generated_at': datetime.now().isoformat(),
            }, f, indent=2, ensure_ascii=False)

        print(f"\n  告警已保存: {output_file}")
        return self.alerts

    # ========= 完整流程 =========
    def full_monitor(self, source_dir='/var/www/html'):
        """执行完整监控流程"""
        print("="*60)
        print("  AWD 日志监控与备份系统")
        print("="*60)

        # 1. 源码备份
        backup_result = self.backup_source(source_dir)

        # 2. 日志分析
        self.analyze_auth_logs()
        self.analyze_web_logs()
        self.analyze_system_logs()

        # 3. 启动实时监控
        monitor_thread = self.start_realtime_monitor(interval=10)

        # 4. 文件完整性监控
        integrity_thread = self.monitor_file_integrity(interval=30)

        # 5. 输出告警
        self.output_alerts()

        # 保持运行
        print("\n[*] 实时监控已启动, 按 Ctrl+C 退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print("\n[*] 正在停止...")
            self.output_alerts()
            self.cleanup_old_logs()
            print("[*] 已停止")


if __name__ == '__main__':
    source_dir = sys.argv[1] if len(sys.argv) > 1 else '/var/www/html'
    monitor = LogMonitor()
    monitor.full_monitor(source_dir)
