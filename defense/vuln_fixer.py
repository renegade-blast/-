#!/usr/bin/env python3
"""
AWD 防御 - 漏洞识别与修复脚本
用途: 代码审计, Web 应用漏洞扫描, 自动修复建议
"""

import os
import re
import sys
import json
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path


class VulnFixer:
    def __init__(self, target_path='/var/www/html', output_file='vuln_report.json'):
        self.target_path = target_path
        self.output_file = output_file
        self.findings = []
        self.fixes_applied = []
        self.backup_dir = '/tmp/awd_fix_backup'

    # ========= 1. 代码审计 - PHP 漏洞 =========
    def audit_php_code(self):
        """审计 PHP 代码安全漏洞"""
        print("\n[*] PHP 代码审计")

        vuln_patterns = {
            'sql_injection': [
                (r'(mysql_query|mysqli_query|->query)\s*\(\s*["\'].*?\$', 'SQL 注入 - 直接拼接 SQL'),
                (r'mysqli_query\s*\(.*\$_(GET|POST|REQUEST)', 'SQL 注入 - 未过滤用户输入'),
                (r'->query\s*\(\s*"SELECT.*?\$', 'SQL 注入 - ORM 拼接'),
                (r'mysql_query\s*\(\s*"INSERT.*?\$', 'SQL 注入 - INSERT 语句'),
            ],
            'command_injection': [
                (r'(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*["\'].*?\$', '命令执行 - 用户可控参数'),
                (r'exec\s*\(\s*\$_[A-Z]+', '代码执行 - eval/exec 用户输入'),
                (r'assert\s*\(\s*\$_[A-Z]+', '代码执行 - assert 用户输入'),
                (r'eval\s*\(\s*\$_[A-Z]+', '代码执行 - eval 用户输入'),
                (r'create_function\s*\(\s*.*\$_[A-Z]+', '代码执行 - create_function'),
                (r'preg_replace\s*\(.*?/e.*?\$_[A-Z]+', '代码执行 - preg_replace /e'),
            ],
            'file_operations': [
                (r'(include|require|include_once|require_once)\s*\(\s*["\']?\$_(GET|POST|REQUEST)', '文件包含 - 用户可控路径'),
                (r'file_get_contents\s*\(\s*["\']?\$_[A-Z]+', '文件读取 - 用户可控路径'),
                (r'file_put_contents\s*\(\s*["\']?\$_[A-Z]+', '文件写入 - 用户可控路径'),
                (r'fopen\s*\(\s*["\']?\$_[A-Z]+', '文件操作 - 用户可控路径'),
                (r'unlink\s*\(\s*["\']?\$_[A-Z]+', '文件删除 - 用户可控路径'),
                (r'copy\s*\(\s*["\']?\$_[A-Z]+', '文件复制 - 用户可控路径'),
            ],
            'xss': [
                (r'echo\s+.*?\$_(GET|POST|REQUEST)', 'XSS - 未过滤直接输出'),
                (r'print\s+.*?\$_(GET|POST|REQUEST)', 'XSS - 未过滤打印'),
                (r'<\?=\s*\$_(GET|POST|REQUEST)', 'XSS - 短标签直接输出'),
                (r'\$_(GET|POST|REQUEST)\[.*?\]\s*\(\)', 'XSS - 模板变量未转义'),
            ],
            'deserialization': [
                (r'unserialize\s*\(\s*\$_[A-Z]+', '反序列化 - 用户可控数据'),
                (r'move_uploaded_file\s*\(.*\$_FILES', '文件上传 - 未过滤'),
                (r'\$_FILES\[.*?\]\[.*?\]', '文件上传 - 直接使用 FILES'),
            ],
            'insecure_config': [
                (r'display_errors\s*=\s*(On|1|True)', '配置 - 错误信息对外显示'),
                (r'expose_php\s*=\s*(On|1|True)', '配置 - PHP 版本暴露'),
                (r'allow_url_include\s*=\s*(On|1|True)', '配置 - 允许 URL include'),
                (r'\$_(GET|POST|REQUEST)\[.*?\]\s*\(', '超全局变量直接使用'),
            ],
        }

        php_files = list(Path(self.target_path).rglob('*.php')) + \
                    list(Path(self.target_path).rglob('*.phtml')) + \
                    list(Path(self.target_path).rglob('*.php5'))

        for php_file in php_files:
            try:
                content = php_file.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')

                for vuln_type, patterns in vuln_patterns.items():
                    for pattern, description in patterns:
                        for line_num, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                finding = {
                                    'type': vuln_type,
                                    'file': str(php_file),
                                    'line': line_num,
                                    'description': description,
                                    'code': line.strip()[:100],
                                    'severity': self._get_severity(vuln_type),
                                }
                                self.findings.append(finding)
            except Exception:
                pass

        # 统计
        type_counts = {}
        for f in self.findings:
            t = f['type']
            type_counts[t] = type_counts.get(t, 0) + 1

        print(f"  审计文件: {len(php_files)} 个 PHP 文件")
        print(f"  发现漏洞: {len(self.findings)} 处")
        for t, count in type_counts.items():
            print(f"    {t}: {count} 处")

    def _get_severity(self, vuln_type):
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'file_operations': 'high',
            'xss': 'medium',
            'deserialization': 'critical',
            'insecure_config': 'medium',
        }
        return severity_map.get(vuln_type, 'low')

    # ========= 2. 配置文件审计 =========
    def audit_config_files(self):
        """审计配置文件安全"""
        print("\n[*] 配置文件审计")

        config_patterns = [
            ('*.php', ['config', 'database', 'db', 'conn', 'settings']),
            ('*.yaml', ['password', 'secret', 'key', 'token']),
            ('*.yml', ['password', 'secret', 'key', 'token']),
            ('*.env', ['DB_PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'ADMIN']),
            ('*.ini', ['password', 'secret']),
            ('*.json', ['password', 'secret', 'api_key', 'token']),
        ]

        sensitive_findings = []

        for ext, keywords in config_patterns:
            files = list(Path(self.target_path).rglob(ext))
            for file in files:
                try:
                    content = file.read_text(encoding='utf-8', errors='ignore')
                    for keyword in keywords:
                        pattern = rf"{keyword}\s*[=:]\s*[\"']?([^\"'\s,;}}\]]{{2,}})"
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            value = match.group(1)
                            if not any(skip in value.lower() for skip in ['null', 'none', 'example', 'your_', 'xxx', 'placeholder']):
                                finding = {
                                    'type': 'sensitive_data',
                                    'file': str(file),
                                    'keyword': keyword,
                                    'value_preview': value[:50] + ('***' if len(value) > 10 else ''),
                                    'severity': 'high',
                                }
                                sensitive_findings.append(finding)
                except Exception:
                    pass

        self.findings.extend(sensitive_findings)
        print(f"  发现敏感信息: {len(sensitive_findings)} 处")

    # ========= 3. 自动修复建议 =========
    def generate_fix_suggestions(self):
        """生成修复建议"""
        print("\n[*] 生成修复建议")

        suggestions = []

        # SQL 注入修复
        sqli_count = len([f for f in self.findings if f['type'] == 'sql_injection'])
        if sqli_count > 0:
            suggestions.append({
                'vuln': 'SQL 注入',
                'count': sqli_count,
                'fix': [
                    '使用预处理语句 (Prepared Statements)',
                    '使用参数化查询',
                    '输入验证 + 白名单过滤',
                    'ORM 参数绑定 (如 PDO/mysqli)',
                ],
                'code_example': '''// 修复前
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysql_query($query);

// 修复后
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([':id' => intval($_GET['id'])]);'''
            })

        # 命令执行修复
        cmd_count = len([f for f in self.findings if f['type'] == 'command_injection'])
        if cmd_count > 0:
            suggestions.append({
                'vuln': '命令执行/代码执行',
                'count': cmd_count,
                'fix': [
                    '禁止使用 eval/assert/system/exec 等危险函数',
                    '输入严格白名单验证',
                    '使用 escapeshellarg() / escapeshellcmd() 转义',
                    '禁用 PHP 危险函数 (disable_functions)',
                ],
                'code_example': '''// php.ini 配置
disable_functions = system,exec,shell_exec,passthru,proc_open,popen,eval,assert

// 代码修复
$cmd = escapeshellarg($_GET['cmd']);
system($cmd);'''
            })

        # 文件操作修复
        file_count = len([f for f in self.findings if f['type'] == 'file_operations'])
        if file_count > 0:
            suggestions.append({
                'vuln': '文件包含/文件操作',
                'count': file_count,
                'fix': [
                    '禁止用户输入直接作为文件路径',
                    '使用白名单验证文件路径',
                    '限制 open_basedir',
                    '使用 basename() 清除路径',
                ],
                'code_example': '''// 修复前
include($_GET['page']);

// 修复后
$page = basename($_GET['page']);
$allowed = ['home', 'about', 'contact'];
if (!in_array($page, $allowed)) die('Invalid page');
include("pages/{$page}.php");'''
            })

        # XSS 修复
        xss_count = len([f for f in self.findings if f['type'] == 'xss'])
        if xss_count > 0:
            suggestions.append({
                'vuln': 'XSS 跨站脚本',
                'count': xss_count,
                'fix': [
                    '输出前进行 HTML 转义',
                    '使用 htmlspecialchars() / htmlentities()',
                    '设置 Content-Security-Policy',
                    '模板引擎自动转义',
                ],
                'code_example': '''// 修复前
echo $_GET['name'];

// 修复后
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');'''
            })

        # 反序列化修复
        deser_count = len([f for f in self.findings if f['type'] == 'deserialization'])
        if deser_count > 0:
            suggestions.append({
                'vuln': '反序列化漏洞',
                'count': deser_count,
                'fix': [
                    '禁止反序列化用户输入',
                    '使用 json_decode 替代 unserialize',
                    '白名单反序列化类',
                ],
                'code_example': '''// 修复前
$data = unserialize($_POST['data']);

// 修复后
$data = json_decode($_POST['data'], true);'''
            })

        # 敏感数据修复
        sens_count = len([f for f in self.findings if f['type'] == 'sensitive_data'])
        if sens_count > 0:
            suggestions.append({
                'vuln': '敏感信息泄露',
                'count': sens_count,
                'fix': [
                    '将敏感配置移到环境变量',
                    '使用加密存储密码',
                    '不在代码中硬编码密钥',
                    '使用 .env 文件 + vlucas/phpdotenv',
                ],
                'code_example': '''// 修复前
$db_password = "admin123";

// 修复后 (使用环境变量)
$db_password = getenv('DB_PASSWORD');'''
            })

        # 输出修复建议
        for s in suggestions:
            print(f"\n  [{s['vuln']}] (共 {s['count']} 处)")
            for fix in s['fix']:
                print(f"    - {fix}")
            print(f"    示例:")
            for line in s['code_example'].split('\n')[:6]:
                print(f"      {line}")

        return suggestions

    # ========= 4. PHP 安全加固 (自动) =========
    def auto_harden_php(self):
        """自动加固 PHP 配置"""
        print("\n[*] PHP 安全加固")

        php_ini_paths = [
            '/etc/php/7.4/apache2/php.ini',
            '/etc/php/8.0/apache2/php.ini',
            '/etc/php/8.1/apache2/php.ini',
            '/etc/php/8.2/apache2/php.ini',
            '/etc/php/7.4/cli/php.ini',
        ]

        harden_rules = {
            'display_errors': 'Off',
            'display_startup_errors': 'Off',
            'log_errors': 'On',
            'error_log': '/var/log/php/error.log',
            'expose_php': 'Off',
            'allow_url_include': 'Off',
            'allow_url_fopen': 'Off',
            'file_uploads': 'On',
            'upload_max_filesize': '2M',
            'post_max_size': '8M',
            'max_execution_time': '30',
            'memory_limit': '128M',
            'disable_functions': 'system,exec,shell_exec,passthru,proc_open,popen,eval,assert,create_function',
            'open_basedir': '/var/www/html:/tmp',
            'disable_classes': '',
            'cgi.fix_pathinfo': '0',
            'session.cookie_httponly': '1',
            'session.cookie_secure': '1',
            'session.cookie_samesite': 'Strict',
        }

        for php_path in php_ini_paths:
            if os.path.exists(php_path):
                try:
                    with open(php_path, 'r') as f:
                        config = f.read()

                    for key, value in harden_rules.items():
                        pattern = rf'^;?\s*{key}\s*=\s*.*'
                        replacement = f'{key} = {value}'
                        if re.search(pattern, config, re.MULTILINE):
                            config = re.sub(pattern, replacement, config, flags=re.MULTILINE)
                        else:
                            config += f'\n{key} = {value}\n'

                    # 备份原文件
                    os.makedirs(self.backup_dir, exist_ok=True)
                    backup_path = os.path.join(self.backup_dir, os.path.basename(php_path) + '.bak')
                    with open(php_path, 'r') as f:
                        original = f.read()
                    with open(backup_path, 'w') as f:
                        f.write(original)

                    with open(php_path, 'w') as f:
                        f.write(config)

                    print(f"  [+] {php_path} 已加固")
                    self.fixes_applied.append(f'php_ini:{php_path}')
                except Exception as e:
                    print(f"  [-] {php_path} 加固失败: {e}")

    # ========= 5. Nginx/Apache 安全加固 =========
    def harden_web_server(self):
        """加固 Web 服务器"""
        print("\n[*] Web 服务器安全加固")

        # Nginx 加固
        nginx_conf = '/etc/nginx/nginx.conf'
        nginx_server_conf = '/etc/nginx/sites-enabled/default'

        nginx_rules = [
            ('server_tokens', 'off'),
            ('client_max_body_size', '2m'),
            ('client_body_timeout', '10'),
            ('client_header_timeout', '10'),
            ('keepalive_timeout', '30'),
            ('send_timeout', '10'),
        ]

        for conf_path in [nginx_conf, nginx_server_conf]:
            if os.path.exists(conf_path):
                try:
                    with open(conf_path, 'r') as f:
                        config = f.read()

                    for key, value in nginx_rules:
                        pattern = rf'^\s*{key}\s+.*;'
                        replacement = f'    {key} {value};'
                        if re.search(pattern, config, re.MULTILINE):
                            config = re.sub(pattern, replacement, config, flags=re.MULTILINE)
                        else:
                            # 在 http/server 块内添加
                            config = re.sub(
                                r'(http\s*\{|server\s*\{)',
                                rf'\1\n    {key} {value};',
                                config, count=1
                            )

                    # 添加安全头
                    security_headers = '''
    # 安全响应头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    '''

                    if 'X-Frame-Options' not in config:
                        # 找到最后一个 } 之前添加
                        config += security_headers

                    # PHP 文件禁止执行
                    php_block = '''
    # 禁止在上传目录执行 PHP
    location ~* /(uploads?|files?|images?|temp)/.*\\.php$ {
        deny all;
    }
    location ~* /(uploads?|files?)/.*\\.(php|phtml|php5)$ {
        deny all;
    }
'''
                    if 'deny all' not in config:
                        config += php_block

                    with open(conf_path, 'w') as f:
                        f.write(config)

                    print(f"  [+] {conf_path} 已加固")
                    self.fixes_applied.append(f'nginx:{conf_path}')
                except Exception as e:
                    print(f"  [-] {conf_path} 加固失败: {e}")

    # ========= 6. 生成报告 =========
    def generate_report(self):
        """生成漏洞报告"""
        print("\n" + "="*60)
        print("  AWD 漏洞审计报告")
        print("="*60)
        print(f"目标路径: {self.target_path}")
        print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"漏洞总数: {len(self.findings)}")
        print(f"已修复: {len(self.fixes_applied)}")

        # 按严重级别统计
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in self.findings:
            s = f.get('severity', 'low')
            severity_counts[s] = severity_counts.get(s, 0) + 1

        for sev, count in severity_counts.items():
            print(f"  {sev}: {count}")

        # 保存为 JSON
        report = {
            'target_path': self.target_path,
            'scan_time': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_summary': severity_counts,
            'findings': self.findings[:50],  # 最多保存 50 条
            'fixes_applied': self.fixes_applied,
        }

        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n  报告已保存: {self.output_file}")
        return report

    # ========= 完整流程 =========
    def full_audit(self):
        """执行完整审计与修复"""
        self.audit_php_code()
        self.audit_config_files()
        self.generate_fix_suggestions()
        self.auto_harden_php()
        self.harden_web_server()
        return self.generate_report()


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '/var/www/html'
    fixer = VulnFixer(target)
    fixer.full_audit()
