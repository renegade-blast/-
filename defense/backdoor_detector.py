#!/usr/bin/env python3
"""
AWD 防御 - 计划任务/后门检测脚本
用途: 检测 crontab 后门, 进程后门, 网络后门, 文件后门
"""

import os
import re
import sys
import json
import subprocess
import hashlib
import time
from datetime import datetime
from pathlib import Path


class BackdoorDetector:
    def __init__(self):
        self.findings = []
        self.baseline_files = {}
        self.quarantined = []

    # ========= 1. Crontab 后门检测 =========
    def check_crontab(self):
        """检测所有 crontab 后门"""
        print("\n[*] Crontab 后门检测")

        suspicious_keywords = [
            'curl', 'wget', 'nc ', 'netcat', 'bash -i', '/dev/tcp',
            'reverse', 'shell', 'backdoor', 'miner', 'minerd',
            'xmrig', 'cryptonight', 'kinsing', 'kdevtmpfsi',
            'nohup', '&>/dev/null', '/tmp/', '/dev/shm/',
            'base64', 'eval', 'assert', 'system(',
            'chmod +s', 'setuid',
            'ssh-key', 'authorized_keys',
        ]

        # 检查所有 crontab 位置
        crontab_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/',
            '/var/spool/cron/',
            '/var/spool/cron/crontabs/',
        ]

        for path in crontab_paths:
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                    self._analyze_crontab_content(content, path, suspicious_keywords)
                except Exception:
                    pass
            elif os.path.isdir(path):
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    if os.path.isfile(item_path):
                        try:
                            with open(item_path, 'r') as f:
                                content = f.read()
                            self._analyze_crontab_content(content, item_path, suspicious_keywords)
                        except Exception:
                            pass

        # 检查用户 crontab
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.stdout:
            self._analyze_crontab_content(result.stdout, 'user_crontab', suspicious_keywords)

        # 检查所有用户的 crontab
        users_result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'],
                                      capture_output=True, text=True)
        if users_result.stdout:
            for user in users_result.stdout.strip().split('\n'):
                if user:
                    cron_path = f'/var/spool/cron/crontabs/{user}'
                    if os.path.exists(cron_path):
                        try:
                            with open(cron_path, 'r') as f:
                                content = f.read()
                            self._analyze_crontab_content(content, cron_path, suspicious_keywords)
                        except Exception:
                            pass

    def _analyze_crontab_content(self, content, source, keywords):
        """分析 crontab 内容"""
        lines = content.strip().split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            for keyword in keywords:
                if keyword.lower() in line.lower():
                    finding = {
                        'type': 'crontab_backdoor',
                        'source': source,
                        'line_num': line_num,
                        'content': line[:200],
                        'keyword': keyword,
                        'severity': 'critical',
                        'action': 'quarantine'
                    }
                    self.findings.append(finding)
                    print(f"  [!!!] Crontab 后门: {source}:{line_num}")
                    print(f"        {line[:100]}")
                    break

    # ========= 2. 进程后门检测 =========
    def check_processes(self):
        """检测可疑进程"""
        print("\n[*] 进程后门检测")

        suspicious_processes = [
            'minerd', 'xmrig', 'cryptonight', 'kinsing', 'kdevtmpfsi',
            'kdevtmpfsi', 'h2Miner', 'kinsing', 'systemd-kworker',
            'cryptonight', 'electroneum', 'cryptonight',
            'bash -i', 'nc ', 'ncat', 'netcat',
            '/dev/tcp', 'reverse', 'backdoor', 'shell',
            '.hidden', '.miner', '.kworker',
        ]

        # 获取所有进程
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                for sus in suspicious_processes:
                    if sus.lower() in line_lower:
                        parts = line.split()
                        pid = parts[1] if len(parts) > 1 else 'unknown'
                        finding = {
                            'type': 'suspicious_process',
                            'pid': pid,
                            'process_info': line[:200],
                            'matched_keyword': sus,
                            'severity': 'critical',
                            'action': 'kill'
                        }
                        self.findings.append(finding)
                        print(f"  [!!!] 可疑进程: PID={pid} {line[:100]}")
                        break

        # 检查隐藏进程
        # 通过 /proc 检查
        try:
            proc_dirs = os.listdir('/proc')
            pids_from_proc = set()
            for d in proc_dirs:
                if d.isdigit():
                    pids_from_proc.add(d)

            ps_result = subprocess.run(['ps', '-eo', 'pid'], capture_output=True, text=True)
            pids_from_ps = set()
            for line in ps_result.stdout.strip().split('\n')[1:]:
                if line.strip():
                    pids_from_ps.add(line.strip())

            # /proc 中有但 ps 看不到 (可能是 rootkit 隐藏的进程)
            hidden_pids = pids_from_proc - pids_from_ps
            for pid in hidden_pids:
                finding = {
                    'type': 'hidden_process',
                    'pid': pid,
                    'severity': 'critical',
                    'action': 'investigate'
                }
                self.findings.append(finding)
                print(f"  [!!!] 隐藏进程: PID={pid}")
        except Exception:
            pass

    # ========= 3. 网络后门检测 =========
    def check_network_backdoors(self):
        """检测网络连接后门"""
        print("\n[*] 网络后门检测")

        # 异常网络连接
        result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
        if not result.stdout:
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)

        if result.stdout:
            lines = result.stdout.strip().split('\n')
            known_services = {'ssh': '22', 'http': '80', 'https': '443',
                              'mysql': '3306', 'redis': '6379', 'ftp': '21'}

            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3] if 'LISTEN' in line else parts[4]
                    port = local_addr.split(':')[-1] if ':' in local_addr else ''

                    # 检查是否为可疑端口
                    if port and port not in [v for v in known_services.values()]:
                        finding = {
                            'type': 'suspicious_port',
                            'info': line[:200],
                            'severity': 'medium',
                            'action': 'investigate'
                        }
                        self.findings.append(finding)
                        print(f"  [!] 可疑端口: {line[:100]}")

        # 检测反弹 Shell (出站连接到奇怪端口)
        est_result = subprocess.run(['ss', '-tnp', 'state', 'established'],
                                    capture_output=True, text=True)
        if est_result.stdout:
            for line in est_result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4]
                    if remote.startswith('127.') or remote.startswith('10.') or remote.startswith('192.168.'):
                        continue  # 本地/内网连接
                    remote_port = remote.split(':')[-1] if ':' in remote else ''
                    if remote_port in ['4444', '4445', '5555', '6666', '7777',
                                       '8888', '9999', '1234', '31337', '88888']:
                        finding = {
                            'type': 'reverse_shell',
                            'remote': remote,
                            'info': line[:200],
                            'severity': 'critical',
                            'action': 'block'
                        }
                        self.findings.append(finding)
                        print(f"  [!!!] 疑似反弹Shell: {line[:100]}")

    # ========= 4. 文件后门检测 =========
    def check_file_backdoors(self):
        """检测文件系统后门"""
        print("\n[*] 文件后门检测")

        # 4a. 检测 /tmp /dev/shm 中的可疑文件
        temp_dirs = ['/tmp', '/dev/shm', '/var/tmp']
        suspicious_extensions = ['.php', '.phtml', '.py', '.pl', '.sh', '.c']
        suspicious_names = ['backdoor', 'shell', 'cmd', 'evil', 'exploit',
                            'payload', 'webshell', 'rootkit', 'hook',
                            'miner', 'crypt', 'xmr', 'kinsing']

        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue
            try:
                for item in os.listdir(temp_dir):
                    item_path = os.path.join(temp_dir, item)
                    item_lower = item.lower()

                    # 检查文件名
                    for sus_name in suspicious_names:
                        if sus_name in item_lower:
                            finding = {
                                'type': 'suspicious_file',
                                'path': item_path,
                                'reason': f'文件名包含 "{sus_name}"',
                                'severity': 'high',
                                'action': 'quarantine'
                            }
                            self.findings.append(finding)
                            print(f"  [!!!] 可疑文件: {item_path}")
                            self.quarantined.append(item_path)
                            break

                    # 检查文件内容
                    if os.path.isfile(item_path):
                        try:
                            with open(item_path, 'r', errors='ignore') as f:
                                content = f.read(2000)

                            dangerous_patterns = [
                                r'eval\s*\(\s*\$_(GET|POST|REQUEST)',
                                r'system\s*\(\s*\$_(GET|POST|REQUEST)',
                                r'exec\s*\(\s*\$_(GET|POST|REQUEST)',
                                r'assert\s*\(\s*\$_(GET|POST|REQUEST)',
                                r'passthru\s*\(\s*\$_(GET|POST|REQUEST)',
                                r'/dev/tcp/',
                                r'reverse.*shell',
                                r'bash\s+-i',
                                r'miner|xmrig|cryptonight',
                                r'socket.*connect',
                            ]

                            for pattern in dangerous_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    finding = {
                                        'type': 'malicious_file',
                                        'path': item_path,
                                        'matched_pattern': pattern,
                                        'severity': 'critical',
                                        'action': 'quarantine'
                                    }
                                    self.findings.append(finding)
                                    print(f"  [!!!] 恶意文件: {item_path}")
                                    self.quarantined.append(item_path)
                                    break
                        except Exception:
                            pass
            except Exception:
                pass

        # 4b. 检查隐藏文件/目录
        hidden_paths = [
            '/var/www/html/.', '/tmp/.', '/var/tmp/.',
        ]
        for hidden_base in hidden_paths:
            base_dir = os.path.dirname(hidden_base)
            if os.path.exists(base_dir):
                try:
                    for item in os.listdir(base_dir):
                        if item.startswith('.') and len(item) > 1:
                            item_path = os.path.join(base_dir, item)
                            if os.path.isfile(item_path) and item.endswith(('.php', '.py', '.sh', '.pl')):
                                finding = {
                                    'type': 'hidden_backdoor',
                                    'path': item_path,
                                    'severity': 'critical',
                                    'action': 'quarantine'
                                }
                                self.findings.append(finding)
                                print(f"  [!!!] 隐藏后门文件: {item_path}")
                                self.quarantined.append(item_path)
                except Exception:
                    pass

        # 4c. 检查 LD_PRELOAD
        ld_preload = '/etc/ld.so.preload'
        if os.path.exists(ld_preload):
            with open(ld_preload, 'r') as f:
                content = f.read().strip()
            if content:
                finding = {
                    'type': 'ld_preload_backdoor',
                    'content': content,
                    'severity': 'critical',
                    'action': 'remove'
                }
                self.findings.append(finding)
                print(f"  [!!!] LD_PRELOAD 后门: {content}")

    # ========= 5. SSH 后门检测 =========
    def check_ssh_backdoors(self):
        """检测 SSH 后门"""
        print("\n[*] SSH 后门检测")

        # 检查 authorized_keys
        ssh_dirs = [
            '/root/.ssh',
            '/home/*/.ssh',
        ]

        for pattern in ssh_dirs:
            if '*' in pattern:
                home_base = '/home'
                if os.path.exists(home_base):
                    for user_dir in os.listdir(home_base):
                        ssh_path = os.path.join(home_base, user_dir, '.ssh', 'authorized_keys')
                        self._check_authorized_keys(ssh_path)
            else:
                self._check_authorized_keys(pattern + '/authorized_keys')

        # 检查 SSH 配置篡改
        ssh_configs = ['/etc/ssh/sshd_config', '/etc/ssh/ssh_config']
        for config_path in ssh_configs:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()

                    suspicious = ['PermitRootLogin yes', 'PasswordAuthentication yes',
                                  'AllowTcpForwarding yes', 'GatewayPorts yes',
                                  'PermitTunnel yes']
                    for sus in suspicious:
                        if sus.lower() in content.lower():
                            finding = {
                                'type': 'ssh_config_issue',
                                'config': config_path,
                                'issue': sus,
                                'severity': 'high'
                            }
                            self.findings.append(finding)
                            print(f"  [!] SSH 配置风险: {config_path} - {sus}")
                except Exception:
                    pass

    def _check_authorized_keys(self, key_path):
        """检查 authorized_keys 文件"""
        if not os.path.exists(key_path):
            return

        try:
            with open(key_path, 'r') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # 检查是否为合法的 SSH 公钥
                    valid_key_types = ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256',
                                       'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                                       'ssh-ed25519', 'sk-ssh-ed25519']
                    if not any(kt in line for kt in valid_key_types):
                        finding = {
                            'type': 'suspicious_ssh_key',
                            'path': key_path,
                            'line': line_num,
                            'content': line[:100],
                            'severity': 'high',
                            'action': 'review'
                        }
                        self.findings.append(finding)
                        print(f"  [!] 可疑 SSH Key: {key_path}:{line_num}")
        except Exception:
            pass

    # ========= 6. 自动处置 =========
    def quarantine_and_clean(self):
        """隔离并清除检测到的后门"""
        print("\n[*] 处置后门")

        quarantined_dir = '/tmp/awd_quarantine'
        os.makedirs(quarantined_dir, exist_ok=True)

        for finding in self.findings:
            action = finding.get('action', 'none')

            if action == 'kill' and 'pid' in finding:
                try:
                    pid = finding['pid']
                    subprocess.run(['kill', '-9', str(pid)], capture_output=True)
                    print(f"  [+] 已查杀进程 PID={pid}")
                except Exception:
                    pass

            elif action == 'quarantine' and 'path' in finding:
                try:
                    src = finding['path']
                    dst = os.path.join(quarantined_dir, os.path.basename(src) + '.quarantine')
                    os.rename(src, dst)
                    print(f"  [+] 已隔离: {src} -> {dst}")
                except Exception:
                    try:
                        os.remove(src)
                        print(f"  [+] 已删除: {src}")
                    except Exception:
                        pass

            elif action == 'remove' and finding.get('type') == 'ld_preload_backdoor':
                try:
                    ld_preload = '/etc/ld.so.preload'
                    with open(ld_preload, 'w') as f:
                        f.write('')
                    print(f"  [+] 已清除 LD_PRELOAD")
                except Exception:
                    pass

            elif action == 'block' and finding.get('type') == 'reverse_shell':
                try:
                    remote = finding.get('remote', '').split(':')[0]
                    subprocess.run(['iptables', '-A', 'OUTPUT', '-d', remote, '-j', 'DROP'],
                                   capture_output=True)
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', remote, '-j', 'DROP'],
                                   capture_output=True)
                    print(f"  [+] 已封禁 IP: {remote}")
                except Exception:
                    pass

    # ========= 7. 基线完整性检查 =========
    def baseline_integrity_check(self):
        """关键文件完整性检查"""
        print("\n[*] 基线完整性检查")

        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/ssh/sshd_config', '/etc/crontab', '/etc/sudoers',
            '/etc/hosts', '/etc/resolv.conf',
            '/bin/bash', '/bin/sh', '/bin/login',
            '/usr/bin/ps', '/usr/bin/top', '/usr/bin/netstat',
            '/usr/bin/find', '/usr/bin/ls', '/usr/bin/awk',
        ]

        violations = []
        for filepath in critical_files:
            if not os.path.exists(filepath):
                continue

            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()
            except Exception:
                continue

            if filepath not in self.baseline_files:
                # 建立基线
                self.baseline_files[filepath] = current_hash
                continue

            if self.baseline_files[filepath] != current_hash:
                finding = {
                    'type': 'integrity_violation',
                    'file': filepath,
                    'severity': 'critical',
                    'action': 'alert'
                }
                violations.append(finding)
                self.findings.append(finding)
                print(f"  [!!!] 文件被篡改: {filepath}")
                print(f"        基线: {self.baseline_files[filepath][:16]}...")
                print(f"        当前: {current_hash[:16]}...")

        if not violations:
            print("  [+] 关键文件完整性正常")

        return violations

    # ========= 完整检测流程 =========
    def full_scan(self):
        """执行完整后门检测"""
        print("="*60)
        print("  AWD 后门检测工具")
        print("="*60)

        self.check_crontab()
        self.check_processes()
        self.check_network_backdoors()
        self.check_file_backdoors()
        self.check_ssh_backdoors()
        self.baseline_integrity_check()
        self.quarantine_and_clean()

        # 汇总
        print("\n" + "="*60)
        print("  后门检测报告")
        print("="*60)
        print(f"  发现问题: {len(self.findings)}")

        if self.findings:
            severity_counts = {}
            for f in self.findings:
                s = f.get('severity', 'low')
                severity_counts[s] = severity_counts.get(s, 0) + 1
            for sev, count in severity_counts.items():
                print(f"    {sev}: {count}")

            for f in self.findings[:20]:
                print(f"    [{f.get('type','')}] {f.get('source','')}{f.get('path','')}{f.get('pid','')}")

        # 保存报告
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'findings': self.findings,
            'quarantined': self.quarantined,
        }
        with open('backdoor_report.json', 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report


if __name__ == '__main__':
    detector = BackdoorDetector()
    detector.full_scan()
