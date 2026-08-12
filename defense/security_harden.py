#!/usr/bin/env python3
"""
AWD 防御 - 权限最小化与账号安全脚本
用途: 限制权限, 加固账号, 清理后门用户, 配置 PAM
"""

import os
import re
import sys
import json
import pwd
import subprocess
from datetime import datetime
from pathlib import Path


class SecurityHardener:
    def __init__(self):
        self.findings = []
        self.actions_taken = []
        self.backup_dir = '/tmp/awd_security_backup'

    # ========= 1. 账号安全审计 =========
    def audit_accounts(self):
        """审计系统账号"""
        print("\n[*] 账号安全审计")

        issues = []

        # 1a. 检查空密码用户
        shadow_path = '/etc/shadow'
        if os.path.exists(shadow_path):
            try:
                with open(shadow_path, 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]
                            if password_hash == '' or password_hash == '!!' or password_hash == '!':
                                # 检查是否锁定
                                if password_hash == '':
                                    issues.append({
                                        'type': 'empty_password',
                                        'user': username,
                                        'description': f'用户 {username} 无密码!',
                                        'severity': 'critical'
                                    })
                                    print(f"  [!!!] 空密码用户: {username}")
            except PermissionError:
                print("  [!] 无权限读取 /etc/shadow")

        # 1b. 检查 UID=0 的非 root 用户
        passwd_path = '/etc/passwd'
        if os.path.exists(passwd_path):
            with open(passwd_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        if uid == '0' and username != 'root':
                            issues.append({
                                'type': 'uid0_non_root',
                                'user': username,
                                'description': f'非 root 用户 {username} 拥有 UID=0 (特权用户)',
                                'severity': 'critical'
                            })
                            print(f"  [!!!] UID=0 后门用户: {username}")

        # 1c. 检查异常用户 (不在常见系统用户列表中)
        system_users = {
            'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
            'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
            'irc', 'gnats', 'nobody', 'systemd-timesync', 'systemd-network',
            'systemd-resolve', 'systemd-bus-proxy', 'messagebus', 'uuidd',
            'dnsmasq', 'usbmuxd', 'rtkit', 'pulse', 'postgres', 'mysql',
            'redis', 'ftp', 'sshd', 'sudo', 'apt', 'ubuntu', 'debian',
        }

        with open(passwd_path, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    uid = int(parts[2])
                    shell = parts[6]
                    # 检查可疑的可登录用户
                    if username not in system_users and uid >= 1000 and uid < 65534:
                        if shell not in ['/usr/sbin/nologin', '/bin/false', '/bin/sync']:
                            issues.append({
                                'type': 'suspicious_user',
                                'user': username,
                                'uid': uid,
                                'shell': shell,
                                'description': f'可疑可登录用户: {username} (UID={uid}, shell={shell})',
                                'severity': 'high'
                            })
                            print(f"  [!] 可疑用户: {username} (UID={uid}, shell={shell})")

        self.findings.extend(issues)
        return issues

    # ========= 2. 清理后门用户 =========
    def remove_backdoor_users(self, confirm=False):
        """移除可疑/后门用户"""
        print("\n[*] 清理后门用户")

        suspicious_users = [
            f['user'] for f in self.findings
            if f['type'] in ['uid0_non_root', 'suspicious_user']
        ]

        if not suspicious_users:
            print("  [+] 无需清理的后门用户")
            return []

        removed = []
        for username in suspicious_users:
            if confirm:
                print(f"  [?] 删除用户 {username}? (y/n)")
                if input().lower() != 'y':
                    continue

            try:
                # 锁定账号
                subprocess.run(['passwd', '-l', username], capture_output=True)
                # 如果 UID=0, 则删除
                passwd_path = '/etc/passwd'
                with open(passwd_path, 'r') as f:
                    lines = f.readlines()

                new_lines = []
                for line in lines:
                    if not line.startswith(f'{username}:'):
                        new_lines.append(line)

                if len(new_lines) < len(lines):
                    # 备份
                    os.makedirs(self.backup_dir, exist_ok=True)
                    with open(os.path.join(self.backup_dir, 'passwd.bak'), 'w') as f:
                        f.writelines(lines)

                    with open(passwd_path, 'w') as f:
                        f.writelines(new_lines)

                    print(f"  [+] 已移除后门用户: {username}")
                    removed.append(username)
                    self.actions_taken.append(f'removed_user:{username}')

            except Exception as e:
                print(f"  [-] 移除 {username} 失败: {e}")

        return removed

    # ========= 3. 强制密码策略 =========
    def enforce_password_policy(self):
        """强制密码安全策略"""
        print("\n[*] 强制密码策略")

        # login.defs 配置
        login_defs = '/etc/login.defs'
        if os.path.exists(login_defs):
            try:
                with open(login_defs, 'r') as f:
                    config = f.read()

                policies = {
                    'PASS_MAX_DAYS': '90',
                    'PASS_MIN_DAYS': '7',
                    'PASS_MIN_LEN': '12',
                    'PASS_WARN_AGE': '14',
                    'LOGIN_RETRIES': '3',
                    'LOGIN_TIMEOUT': '60',
                    'UMASK': '027',
                }

                for key, value in policies.items():
                    pattern = rf'^\s*{key}\s+\d+'
                    replacement = f'{key} {value}'
                    if re.search(pattern, config, re.MULTILINE):
                        config = re.sub(pattern, replacement, config, flags=re.MULTILINE)
                    else:
                        config += f'\n{key} {value}\n'

                # 备份
                os.makedirs(self.backup_dir, exist_ok=True)
                with open(os.path.join(self.backup_dir, 'login.defs.bak'), 'w') as f:
                    f.write(open(login_defs).read())

                with open(login_defs, 'w') as f:
                    f.write(config)

                print(f"  [+] {login_defs} 已更新")
                self.actions_taken.append('password_policy:updated')
            except Exception as e:
                print(f"  [-] 密码策略更新失败: {e}")

        # 创建密码强度检查
        pwquality_conf = '/etc/security/pwquality.conf'
        try:
            pwquality_config = """# 密码强度配置
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 4
maxlogins = 3
"""
            with open(pwquality_conf, 'w') as f:
                f.write(pwquality_config)
            print(f"  [+] {pwquality_conf} 已创建")
        except Exception as e:
            print(f"  [-] pwquality 配置失败: {e}")

    # ========= 4. SSH 安全加固 =========
    def harden_ssh(self):
        """加固 SSH 配置"""
        print("\n[*] SSH 安全加固")

        ssh_config = '/etc/ssh/sshd_config'
        if not os.path.exists(ssh_config):
            print("  [!] SSH 配置不存在")
            return

        try:
            with open(ssh_config, 'r') as f:
                config = f.read()

            harden_rules = {
                'PermitRootLogin': 'no',
                'PasswordAuthentication': 'no',
                'PubkeyAuthentication': 'yes',
                'MaxAuthTries': '3',
                'LoginGraceTime': '30',
                'AllowTcpForwarding': 'no',
                'X11Forwarding': 'no',
                'ClientAliveInterval': '300',
                'ClientAliveCountMax': '2',
                'UsePAM': 'yes',
                'AllowUsers': '',
            }

            for key, value in harden_rules.items():
                pattern = rf'^#?\s*{key}\s+.*'
                replacement = f'{key} {value}'
                if re.search(pattern, config, re.MULTILINE):
                    config = re.sub(pattern, replacement, config, flags=re.MULTILINE)
                else:
                    config += f'\n{key} {value}\n'

            # 备份原配置
            os.makedirs(self.backup_dir, exist_ok=True)
            with open(os.path.join(self.backup_dir, 'sshd_config.bak'), 'w') as f:
                f.write(open(ssh_config).read())

            with open(ssh_config, 'w') as f:
                f.write(config)

            # 重启 SSH
            subprocess.run(['service', 'ssh', 'restart'], capture_output=True, timeout=5)

            print(f"  [+] SSH 已加固并重启")
            self.actions_taken.append('ssh_hardened')
        except Exception as e:
            print(f"  [-] SSH 加固失败: {e}")

    # ========= 5. 权限最小化 - Web 目录 =========
    def minimize_web_permissions(self, web_root='/var/www/html'):
        """最小化 Web 目录权限"""
        print(f"\n[*] Web 目录权限最小化: {web_root}")

        if not os.path.exists(web_root):
            print(f"  [!] {web_root} 不存在")
            return

        try:
            # 设置所有者
            subprocess.run(
                ['chown', '-R', 'www-data:www-data', web_root],
                capture_output=True
            )

            # 设置目录权限 (755)
            subprocess.run(
                ['find', web_root, '-type', 'd', '-exec', 'chmod', '755', '{}', ';'],
                capture_output=True
            )

            # 设置文件权限 (644)
            subprocess.run(
                ['find', web_root, '-type', 'f', '-exec', 'chmod', '644', '{}', ';'],
                capture_output=True
            )

            # 配置文件更严格
            sensitive_exts = ['.conf', '.ini', '.env', '.sql', '.bak']
            for ext in sensitive_exts:
                subprocess.run(
                    ['find', web_root, '-name', f'*{ext}', '-exec', 'chmod', '600', '{}', ';'],
                    capture_output=True
                )

            # 禁止 Web 目录可写 (除 uploads 外)
            upload_dirs = ['uploads', 'upload', 'files', 'images', 'tmp', 'temp', 'cache']
            for root, dirs, files in os.walk(web_root):
                dirname = os.path.basename(root)
                if dirname not in upload_dirs and dirname not in ['', '.', '..']:
                    os.chmod(root, 0o755)

            # 上传目录限制执行
            for upload_dir in upload_dirs:
                dir_path = os.path.join(web_root, upload_dir)
                if os.path.exists(dir_path):
                    # 添加 .htaccess 禁止 PHP 执行
                    htaccess_content = "php_flag engine off\nRemoveHandler .php .phtml\n"
                    htaccess_path = os.path.join(dir_path, '.htaccess')
                    with open(htaccess_path, 'w') as f:
                        f.write(htaccess_content)

            print(f"  [+] {web_root} 权限已最小化")
            self.actions_taken.append(f'web_permissions_minimized:{web_root}')
        except Exception as e:
            print(f"  [-] 权限设置失败: {e}")

    # ========= 6. 文件系统权限检查 =========
    def audit_file_permissions(self):
        """审计关键文件权限"""
        print("\n[*] 文件权限审计")

        critical_files = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/ssh/sshd_config': '644',
            '/etc/crontab': '644',
            '/etc/sudoers': '440',
            '/root/.ssh/authorized_keys': '600',
            '/root/.bashrc': '644',
        }

        issues = []
        for filepath, expected_perm in critical_files.items():
            if os.path.exists(filepath):
                stat = os.stat(filepath)
                current_perm = oct(stat.st_mode)[-3:]
                if current_perm != expected_perm:
                    issues.append({
                        'type': 'permission_issue',
                        'file': filepath,
                        'expected': expected_perm,
                        'current': current_perm,
                        'severity': 'high'
                    })
                    print(f"  [!] {filepath}: 期望 {expected_perm}, 当前 {current_perm}")

                    # 自动修复
                    try:
                        os.chmod(filepath, int(expected_perm, 8))
                        print(f"    [+] 已修复为 {expected_perm}")
                        self.actions_taken.append(f'fixed:{filepath}:{expected_perm}')
                    except PermissionError:
                        pass

        # 检查世界可写的目录
        world_writable = []
        for root, dirs, files in os.walk('/var/www/html'):
            for d in dirs:
                dir_path = os.path.join(root, d)
                try:
                    mode = os.stat(dir_path).st_mode
                    if mode & 0o002:  # 世界可写
                        world_writable.append(dir_path)
                        print(f"  [!] 世界可写目录: {dir_path}")
                except Exception:
                    pass

        # /tmp 挂载选项
        try:
            result = subprocess.run(['mount'], capture_output=True, text=True)
            if '/tmp' in result.stdout:
                if 'noexec' not in result.stdout and 'nosuid' not in result.stdout:
                    print("  [!] /tmp 未设置 noexec,nosuid")
                    # 尝试重新挂载
                    subprocess.run(['mount', '-o', 'remount,nodev,nosuid,noexec', '/tmp'],
                                   capture_output=True, timeout=5)
        except Exception:
            pass

        self.findings.extend(issues)
        return issues

    # ========= 7. 完整安全加固流程 =========
    def full_harden(self, web_root='/var/www/html'):
        """执行完整安全加固"""
        print("="*60)
        print("  AWD 权限最小化与账号安全")
        print("="*60)

        self.audit_accounts()
        self.remove_backdoor_users(confirm=False)
        self.enforce_password_policy()
        self.harden_ssh()
        self.audit_file_permissions()
        self.minimize_web_permissions(web_root)

        # 结果汇总
        print("\n" + "="*60)
        print("  安全加固完成")
        print("="*60)
        print(f"  发现问题: {len(self.findings)}")
        print(f"  已执行操作: {len(self.actions_taken)}")
        for action in self.actions_taken:
            print(f"    - {action}")

        # 保存报告
        report = {
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings,
            'actions': self.actions_taken,
        }
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report


if __name__ == '__main__':
    web_root = sys.argv[1] if len(sys.argv) > 1 else '/var/www/html'
    hardener = SecurityHardener()
    hardener.full_harden(web_root)
