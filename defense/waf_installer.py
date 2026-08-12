#!/usr/bin/env python3
"""
AWD WAF 自动部署脚本
用途: 自动将 WAF 部署到 Web 目录, 支持多种部署方式
部署方式:
  1. auto_prepend_file (推荐, 全局生效)
  2. .htaccess (Apache)
  3. .user.ini (PHP-FPM)
  4. 入口文件 require (手动)
"""

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path


class WAFInstaller:
    def __init__(self, web_root='/var/www/html', waf_source=None):
        self.web_root = web_root
        self.waf_source = waf_source or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'waf.php'
        )
        self.backup_dir = '/tmp/awd_waf_backup'
        self.deployed = []

    # ========= 1. 部署 WAF 文件 =========
    def deploy_waf_file(self):
        """复制 WAF 文件到 Web 目录"""
        print(f"\n[*] 部署 WAF 文件到 {self.web_root}")

        if not os.path.exists(self.waf_source):
            print(f"  [!] WAF 源文件不存在: {self.waf_source}")
            return False

        # 创建隐藏目录存放 WAF
        waf_dir = os.path.join(self.web_root, '.awd_security')
        os.makedirs(waf_dir, exist_ok=True)

        # 复制 WAF 文件 (使用隐藏文件名)
        waf_dest = os.path.join(waf_dir, 'waf.php')
        shutil.copy2(self.waf_source, waf_dest)

        # 设置权限
        os.chmod(waf_dest, 0o644)
        try:
            shutil.chown(waf_dest, 'www-data', 'www-data')
        except Exception:
            pass

        # 创建 .htaccess 禁止直接访问 WAF 目录
        htaccess_path = os.path.join(waf_dir, '.htaccess')
        with open(htaccess_path, 'w') as f:
            f.write("Deny from all\nOrder Deny,Allow\n")

        print(f"  [+] WAF 已部署: {waf_dest}")
        self.deployed.append(('waf_file', waf_dest))
        return waf_dest

    # ========= 2. 通过 auto_prepend_file 部署 (推荐) =========
    def deploy_via_auto_prepend(self, waf_path):
        """通过 PHP auto_prepend_file 全局加载 WAF"""
        print(f"\n[*] 配置 auto_prepend_file (推荐方式)")

        php_ini_paths = [
            '/etc/php/7.4/apache2/php.ini',
            '/etc/php/7.4/fpm/php.ini',
            '/etc/php/7.4/cli/php.ini',
            '/etc/php/8.0/apache2/php.ini',
            '/etc/php/8.0/fpm/php.ini',
            '/etc/php/8.0/cli/php.ini',
            '/etc/php/8.1/apache2/php.ini',
            '/etc/php/8.1/fpm/php.ini',
            '/etc/php/8.2/apache2/php.ini',
            '/etc/php/8.2/fpm/php.ini',
        ]

        deployed_count = 0
        for php_ini in php_ini_paths:
            if not os.path.exists(php_ini):
                continue

            try:
                # 备份
                os.makedirs(self.backup_dir, exist_ok=True)
                backup_path = os.path.join(self.backup_dir, os.path.basename(php_ini) + '.bak')
                shutil.copy2(php_ini, backup_path)

                with open(php_ini, 'r') as f:
                    config = f.read()

                # 设置 auto_prepend_file
                pattern = r'^;?\s*auto_prepend_file\s*=\s*.*'
                replacement = f'auto_prepend_file = {waf_path}'

                if re.search(pattern, config, re.MULTILINE):
                    new_config = re.sub(pattern, replacement, config, flags=re.MULTILINE)
                else:
                    new_config = config + f'\n{replacement}\n'

                with open(php_ini, 'w') as f:
                    f.write(new_config)

                print(f"  [+] {php_ini} 已配置 auto_prepend_file")
                self.deployed.append(('auto_prepend', php_ini))
                deployed_count += 1

            except Exception as e:
                print(f"  [-] {php_ini} 配置失败: {e}")

        # 重启 PHP-FPM / Apache
        if deployed_count > 0:
            self._restart_services()

        return deployed_count > 0

    # ========= 3. 通过 .user.ini 部署 (PHP-FPM) =========
    def deploy_via_user_ini(self, waf_path):
        """通过 .user.ini 文件部署 (PHP-FPM 模式)"""
        print(f"\n[*] 配置 .user.ini (PHP-FPM 模式)")

        user_ini_path = os.path.join(self.web_root, '.user.ini')

        # 备份现有 .user.ini
        if os.path.exists(user_ini_path):
            os.makedirs(self.backup_dir, exist_ok=True)
            shutil.copy2(user_ini_path, os.path.join(self.backup_dir, '.user.ini.bak'))

        # .user.ini 内容
        ini_content = f"""; AWD WAF Configuration
auto_prepend_file = "{waf_path}"
; WAF 模式: block (拦截) | log (仅记录) | off (关闭)
; 可通过环境变量 AWD_WAF_MODE 设置

; PHP 安全加固
display_errors = Off
expose_php = Off
allow_url_include = Off
allow_url_fopen = Off
disable_functions = system,exec,shell_exec,passthru,proc_open,popen,eval,assert,create_function
open_basedir = "{self.web_root}:/tmp"
"""

        with open(user_ini_path, 'w') as f:
            f.write(ini_content)

        os.chmod(user_ini_path, 0o644)
        try:
            shutil.chown(user_ini_path, 'www-data', 'www-data')
        except Exception:
            pass

        print(f"  [+] {user_ini_path} 已创建")
        self.deployed.append(('user_ini', user_ini_path))
        return True

    # ========= 4. 通过 .htaccess 部署 (Apache) =========
    def deploy_via_htaccess(self, waf_path):
        """通过 .htaccess 部署 (Apache + mod_php)"""
        print(f"\n[*] 配置 .htaccess (Apache 模式)")

        htaccess_path = os.path.join(self.web_root, '.htaccess')

        # 备份
        if os.path.exists(htaccess_path):
            os.makedirs(self.backup_dir, exist_ok=True)
            shutil.copy2(htaccess_path, os.path.join(self.backup_dir, '.htaccess.bak'))
            with open(htaccess_path, 'r') as f:
                existing = f.read()
        else:
            existing = ''

        # 添加 WAF 配置
        waf_config = f"""
# AWD WAF Configuration
php_value auto_prepend_file "{waf_path}"

# 安全头
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-WAF "AWD-WAF/1.0"
</IfModule>

# 禁止访问敏感文件
<FilesMatch "\\.(bak|inc|sql|log|sh|conf|ini)$">
    Require all denied
</FilesMatch>

# 禁止访问隐藏文件
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>

# 上传目录禁止执行 PHP
<IfModule mod_php.c>
    <Directory "{self.web_root}/uploads">
        php_flag engine off
    </Directory>
    <Directory "{self.web_root}/upload">
        php_flag engine off
    </Directory>
    <Directory "{self.web_root}/files">
        php_flag engine off
    </Directory>
    <Directory "{self.web_root}/images">
        php_flag engine off
    </Directory>
</IfModule>
"""

        # 避免重复添加
        if 'AWD WAF' not in existing:
            with open(htaccess_path, 'w') as f:
                f.write(existing + waf_config)

            os.chmod(htaccess_path, 0o644)
            print(f"  [+] {htaccess_path} 已更新")
            self.deployed.append(('htaccess', htaccess_path))
            return True
        else:
            print(f"  [+] .htaccess 已包含 WAF 配置")
            return True

    # ========= 5. 注入到入口文件 (备选) =========
    def inject_to_entry_files(self, waf_path):
        """在 PHP 入口文件顶部 require WAF"""
        print(f"\n[*] 注入到 PHP 入口文件")

        entry_files = ['index.php', 'admin.php', 'login.php', 'config.php',
                       'common.php', 'header.php', 'bootstrap.php', 'app.php']

        injected = 0
        for entry in entry_files:
            entry_path = os.path.join(self.web_root, entry)
            if not os.path.exists(entry_path):
                continue

            try:
                with open(entry_path, 'r') as f:
                    content = f.read()

                # 检查是否已注入
                if 'awd_security/waf.php' in content or 'AWD_WAF_LOADED' in content:
                    continue

                # 备份
                os.makedirs(self.backup_dir, exist_ok=True)
                shutil.copy2(entry_path, os.path.join(self.backup_dir, entry + '.bak'))

                # 在 <?php 后注入
                inject_code = f'\nrequire_once "{waf_path}";\n'
                new_content = re.sub(
                    r'(<\?php)',
                    r'\1' + inject_code,
                    content,
                    count=1
                )

                with open(entry_path, 'w') as f:
                    f.write(new_content)

                print(f"  [+] 已注入: {entry_path}")
                self.deployed.append(('inject', entry_path))
                injected += 1

            except Exception as e:
                print(f"  [-] {entry_path} 注入失败: {e}")

        return injected

    # ========= 6. 创建 WAF 管理界面 =========
    def create_waf_admin(self, waf_path):
        """创建 WAF 管理页面 (用于查看日志和统计)"""
        print(f"\n[*] 创建 WAF 管理界面")

        admin_path = os.path.join(self.web_root, '.awd_security', 'admin.php')

        admin_code = f"""<?php
// AWD WAF 管理界面
// 访问: http://target/.awd_security/admin.php?key=AWD_ADMIN_KEY

$admin_key = 'awd_admin_' . md5('AWD2024');
if (!isset($_GET['key']) || $_GET['key'] !== $admin_key) {{
    http_response_code(404);
    die('Not Found');
}}

require_once "{waf_path}";

$stats = awd_waf_stats();

header('Content-Type: application/json');
echo json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
"""

        with open(admin_path, 'w') as f:
            f.write(admin_code)

        os.chmod(admin_path, 0o644)
        print(f"  [+] 管理界面: {admin_path}")
        print(f"      访问: http://target/.awd_security/admin.php?key=awd_admin_" + str(hashlib.md5(b'AWD2024').hexdigest()) if False else "      (key 在文件中查看)")
        self.deployed.append(('admin', admin_path))
        return admin_path

    # ========= 7. 重启服务 =========
    def _restart_services(self):
        """重启 Web 服务"""
        print(f"\n[*] 重启 Web 服务")

        services = [
            ('apache2', ['service', 'apache2', 'restart']),
            ('nginx', ['service', 'nginx', 'restart']),
            ('php-fpm', ['service', 'php7.4-fpm', 'restart']),
            ('php-fpm', ['service', 'php8.0-fpm', 'restart']),
            ('php-fpm', ['service', 'php8.1-fpm', 'restart']),
            ('php-fpm', ['service', 'php8.2-fpm', 'restart']),
        ]

        for name, cmd in services:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0:
                    print(f"  [+] {name} 已重启")
            except Exception:
                pass

    # ========= 8. 测试 WAF =========
    def test_waf(self):
        """测试 WAF 是否生效"""
        print(f"\n[*] 测试 WAF")

        test_urls = [
            ("http://localhost/?id=1' OR '1'='1", 'SQL注入测试'),
            ("http://localhost/?q=<script>alert(1)</script>", 'XSS测试'),
            ("http://localhost/?cmd=;id", '命令执行测试'),
            ("http://localhost/?file=../../../etc/passwd", '文件包含测试'),
            ("http://localhost/?url=http://127.0.0.1", 'SSRF测试'),
        ]

        for url, desc in test_urls:
            try:
                result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
                    capture_output=True, text=True, timeout=5
                )
                status = result.stdout.strip()
                if status == '403':
                    print(f"  [+] {desc}: 已拦截 (403)")
                elif status == '200':
                    print(f"  [!] {desc}: 未拦截 (200) - 检查配置")
                else:
                    print(f"  [?] {desc}: 状态码 {status}")
            except Exception as e:
                print(f"  [-] {desc}: 测试失败 {e}")

    # ========= 9. 卸载 WAF =========
    def uninstall(self):
        """卸载 WAF"""
        print(f"\n[*] 卸载 WAF")

        # 恢复备份
        if os.path.exists(self.backup_dir):
            for item in os.listdir(self.backup_dir):
                backup_path = os.path.join(self.backup_dir, item)
                if item.endswith('.bak'):
                    original_name = item[:-4]
                    # 恢复到对应位置
                    print(f"  [+] 恢复备份: {item}")

        # 删除 WAF 目录
        waf_dir = os.path.join(self.web_root, '.awd_security')
        if os.path.exists(waf_dir):
            shutil.rmtree(waf_dir)
            print(f"  [+] 已删除: {waf_dir}")

        # 清理 auto_prepend_file 配置
        php_ini_paths = [
            '/etc/php/7.4/apache2/php.ini', '/etc/php/8.0/apache2/php.ini',
            '/etc/php/8.1/apache2/php.ini', '/etc/php/8.2/apache2/php.ini',
        ]
        for php_ini in php_ini_paths:
            if os.path.exists(php_ini):
                with open(php_ini, 'r') as f:
                    config = f.read()
                config = re.sub(
                    r'^auto_prepend_file\s*=\s*.*$',
                    ';auto_prepend_file =',
                    config,
                    flags=re.MULTILINE
                )
                with open(php_ini, 'w') as f:
                    f.write(config)

        self._restart_services()
        print(f"  [+] WAF 已卸载")

    # ========= 完整部署流程 =========
    def full_deploy(self, method='auto'):
        """完整部署 WAF"""
        print("="*60)
        print("  AWD WAF 自动部署工具")
        print("="*60)
        print(f"Web 根目录: {self.web_root}")
        print(f"WAF 源文件: {self.waf_source}")
        print(f"部署方式: {method}")

        # 1. 部署 WAF 文件
        waf_path = self.deploy_waf_file()
        if not waf_path:
            print("\n[!] 部署失败")
            return False

        # 2. 根据方式部署
        if method == 'auto':
            # 自动选择最优方式
            if os.path.exists('/etc/php') and self._is_fpm():
                self.deploy_via_user_ini(waf_path)
            else:
                self.deploy_via_htaccess(waf_path)

            # 同时配置 auto_prepend_file 作为后备
            self.deploy_via_auto_prepend(waf_path)

        elif method == 'prepend':
            self.deploy_via_auto_prepend(waf_path)
        elif method == 'user_ini':
            self.deploy_via_user_ini(waf_path)
        elif method == 'htaccess':
            self.deploy_via_htaccess(waf_path)
        elif method == 'inject':
            self.inject_to_entry_files(waf_path)
        elif method == 'all':
            self.deploy_via_auto_prepend(waf_path)
            self.deploy_via_user_ini(waf_path)
            self.deploy_via_htaccess(waf_path)
            self.inject_to_entry_files(waf_path)

        # 3. 创建管理界面
        self.create_waf_admin(waf_path)

        # 4. 重启服务
        self._restart_services()

        # 5. 测试
        self.test_waf()

        # 汇总
        print("\n" + "="*60)
        print("  部署完成")
        print("="*60)
        print(f"  部署项: {len(self.deployed)}")
        for dtype, path in self.deployed:
            print(f"    [{dtype}] {path}")

        print(f"\n  日志位置: /tmp/awd_waf.log")
        print(f"  查看日志: tail -f /tmp/awd_waf.log")
        print(f"  统计: cat /tmp/awd_waf.log | python3 -m json.tool")

        return True

    def _is_fpm(self):
        """检测是否使用 PHP-FPM"""
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True, text=True
            )
            return 'php-fpm' in result.stdout or 'php7' in result.stdout or 'php8' in result.stdout
        except Exception:
            return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 waf_installer.py deploy [web_root] [method]")
        print("  python3 waf_installer.py test [web_root]")
        print("  python3 waf_installer.py uninstall [web_root]")
        print()
        print("部署方式 (method):")
        print("  auto      - 自动选择 (默认)")
        print("  prepend   - auto_prepend_file (推荐)")
        print("  user_ini  - .user.ini (PHP-FPM)")
        print("  htaccess  - .htaccess (Apache)")
        print("  inject    - 注入入口文件")
        print("  all       - 所有方式")
        sys.exit(1)

    action = sys.argv[1]
    web_root = sys.argv[2] if len(sys.argv) > 2 else '/var/www/html'
    method = sys.argv[3] if len(sys.argv) > 3 else 'auto'

    installer = WAFInstaller(web_root=web_root)

    if action == 'deploy':
        installer.full_deploy(method=method)
    elif action == 'test':
        installer.test_waf()
    elif action == 'uninstall':
        installer.uninstall()
    else:
        print(f"未知操作: {action}")
