# Crypto 攻防深度手册

## 1. 对称加密攻击

### 1.1 AES-ECB 攻击

```python
# ECB 相同明文块 → 相同密文块 → 可拼图
# 攻击: 逐字节爆破

def ecb_oracle(encrypt_fn, block_size=16):
    """AES-ECB 逐字节爆破"""
    known = b''
    for pos in range(block_size):
        # 填充使目标字节在块边界
        padding_len = block_size - 1 - pos
        prefix = b'A' * padding_len
        target_byte = encrypt_fn(prefix + b'X' + known + b'A')
        # 爆破下一个字节
        for guess in range(256):
            payload = prefix + bytes([guess]) + known + b'A'
            cipher = encrypt_fn(payload)
            if cipher[:block_size] == target_byte[:block_size]:
                known += bytes([guess])
                break
    return known

# 实际攻击示例
# flag = ecb_oracle(lambda x: oracle_encrypt(x))
```

### 1.2 AES-CBC Padding Oracle

```python
# CBC 模式: C[i] = E(P[i] XOR C[i-1])
# 解密时: P[i] = D(C[i]) XOR C[i-1]
# 改变 C[i-1] 的字节可以改变 P[i] 的对应字节

def padding_oracle_attack(ciphertext, oracle, block_size=16):
    """Padding Oracle 攻击 CBC"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''

    for block_idx in range(1, len(blocks)):
        prev = bytearray(blocks[block_idx-1])
        current = blocks[block_idx]
        decrypted = bytearray(block_size)

        for pos in range(block_size-1, -1, -1):
            pad_val = block_size - pos
            # 调整已知字节使 padding 正确
            for k in range(pos+1, block_size):
                prev[k] = decrypted[k] ^ pad_val

            found = False
            for guess in range(256):
                prev[pos] = guess
                modified = bytes(prev) + current
                if oracle(modified):  # 返回 True 表示 padding 正确
                    decrypted[pos] = guess ^ pad_val
                    found = True
                    break
            if not found:
                decrypted[pos] = pad_val ^ pad_val  # 默认

        plaintext += bytes([decrypted[i] ^ blocks[block_idx-1][i] for i in range(block_size)])

    return plaintext
```

### 1.3 DES 暴力破解

```python
# DES 56 位密钥可穷举
# 使用 Python 多进程并行

from Crypto.Cipher import DES
import itertools

def break_des(ciphertext, plaintext_sample):
    """暴力破解 DES"""
    for key_int in range(2**56):
        key = key_int.to_bytes(7, 'big')
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        if plaintext_sample in decrypted:
            return key, decrypted
    return None
```

### 1.4 RC4 攻击

```python
# RC4 密钥调度缺陷
# Fluhrer-Mantin-Shamir Attack
# 已知大量密钥流字节可还原密钥

def rc4_crypt(key, data):
    """RC4 加密"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)
```

### 1.5 AES-GCM Nonce 重用攻击

```python
# GCM 使用相同 nonce + 不同明文 → 泄漏 XOR 关系
# C1 XOR C2 = P1 XOR P2 (当 nonce 相同时)

# 攻击: 收集大量使用同一 nonce 的密文
# 若已知 P1 的部分内容, 可推断 P2 的对应位置
# C1 XOR C2 = P1 XOR P2
# P2 = C1 XOR C2 XOR P1
```

---

## 2. 非对称加密攻击 (RSA)

### 2.1 RSA 基础

```python
from Crypto.Util.number import *

# RSA 参数
n = p * q                    # 模数
e = 65537                    # 公钥指数
d = inverse(e, phi(n))       # 私钥指数
phi_n = (p-1) * (q-1)        # 欧拉函数
c = pow(m, e, n)             # 加密
m = pow(c, d, n)             # 解密

# 扩展欧几里得算法
def egcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

def inverse(a, m):
    g, x, _ = egcd(a, m)
    return x % m
```

### 2.2 Wiener 攻击 (小私钥指数 d)

```python
from Crypto.Util.number import long_to_bytes

def wiener_attack(n, e):
    """Wiener 攻击: d < n^0.25 / 3"""
    # 连分数展开
    def continued_fraction(num, den):
        while den:
            yield num // den
            num, den = den, num % den

    def convergents(cf):
        old_h, h = 0, 1
        old_k, k = 1, 0
        for a in cf:
            old_h, h = h, a * h + old_h
            old_k, k = k, a * k + old_k
            yield h, k

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = int(n - phi + 1) // 2
            t = int(s * s - 4 * n)
            if t >= 0:
                sqrt_t = integer_sqrt(t)
                if sqrt_t * sqrt_t == t:
                    p = (s + sqrt_t) // 2
                    q = (s - sqrt_t) // 2
                    if p * q == n:
                        return d
    return None

# 使用
d = wiener_attack(n, e)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

### 2.3 Hastad 攻击 (低加密指数广播)

```python
# 多个密文共用 e=3, 不同 n
# CRT 合并后开 e 次方

from Crypto.Util.number import long_to_bytes

def hastad_attack(e, c_list, n_list):
    """Hastad Broadcast 攻击"""
    # CRT 合并
    N = 1
    for n in n_list: N *= n

    def crt(c, n):
        Mi = N // n
        yi = inverse(Mi, n)
        return (c * Mi * yi) % N

    C = sum(crt(c, n) for c, n in zip(c_list, n_list)) % N
    m = integer_nthroot(C, e)[0]
    return long_to_bytes(m)
```

### 2.4 共模攻击 (公共模数)

```python
# 两个人用相同 n, 不同 e, 加密同一消息
# gcd(e1, e2) = 1 时可恢复 m

def common_modulus_attack(n, e1, e2, c1, c2):
    """共模攻击"""
    g, s1, s2 = egcd(e1, e2)
    # s1*e1 + s2*e2 = g
    if s1 < 0:
        c1 = inverse(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = inverse(c2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m
```

### 2.5 Pollard p-1 分解

```python
# p-1 光滑时可快速分解
# 找到 q | p-1, q 是小素数

def pollard_p1(n, B=100000):
    """Pollard p-1 分解"""
    a = 2
    primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]
    for p in primes:
        pe = p
        while pe * p <= B: pe *= p
        a = pow(a, pe, n)
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None
```

### 2.6 Coppersmith 攻击 (小 e + 共前缀)

```python
# 已知明文高位, 恢复低位
# 使用 SageMath:
# # 给定: n, e, c, 已知 m 的前 k 位
# # 求: m = known + unknown 中 unknown 部分
# # 转化为: f(x) = (known + x)^e - c (mod n)
# # 用 Coppersmith 的小根定理求解
```

### 2.7 RsaCtfTool 实用

```python
from RsaCtfTool.RsaCtfAttack import RsaAttack
from RsaCtfTool.attacks.wiener import WienerAttack
from RsaCtfTool.attacks.hastad import HastadAttack
from RsaCtfTool.attacks.common_modulus import CommonModulusAttack

# 使用示例
# python3 RsaCtfTool.py -n N -e E -c C --attack wiener
# python3 RsaCtfTool.py -n N1,N2,N3 -e 3 -c C1,C2,C3 --attack hastad
```

### 2.8 SageMath 攻击示例

```sage
# 分解
# Pollard rho
def pollard_rho(n, max_iter=100000):
    x = Zmod(n).random_element()
    y = x
    d = 1
    while d == 1:
        x = x^2 + 1
        y = (y^2 + 1)^2 + 1
        d = gcd(abs(x - y), n)
        max_iter -= 1
        if max_iter <= 0: return None
    return d if d != n else None

# Coppersmith 小根
# 给定 f(x) = x^e - c (mod n), 求小根
# sage:
# N = 123456789012345678901234567890
# e = 3
# c = 123456789012345678901234567890
# X = 10^30  # 根的上界
# f = x^e - c
# beta = 0.5  # Coppersmith 参数
# t = 1 + floor(log(N)/log(X)) * floor(beta)
# Hensel lifting + 格规约
```

---

## 3. 哈希攻击

### 3.1 碰撞攻击

```python
# MD5/SHA1 已不安全
# 生日攻击: 找 2^64 次运算的 MD5 碰撞

# Hash 长度扩展
# 给定: hash(m) = h, |m| = len
# 求: hash(m + append) = h' （不知道 m 内容）

def hash_length_extension(hash_func, original_hash, original_len, append):
    """Hash 长度扩展攻击"""
    # 伪造消息
    # H(original || padding || append)
    # padding: 按 hash 算法要求填充
    # 新 hash = H(hash_output || append)
    pass

# 常用工具: hash_extender
# ./hash_extender -d <original_hash> -s <original_len> -a <append>
```

### 3.2 彩虹表反查

```bash
# 在线彩虹表
# https://www.cmd5.org/
# https://hashkiller.co.uk/

# 本地工具
# rainbowcrack, ophcrack

# 生成彩虹表
rtgen md5_lowercase_#1-7
# 反查
rtsort *.rt
rt2rc md5_lowercase_#1-7_hash.rk hash_value
```

### 3.3 哈希序位碰撞

```python
# 利用可控输入+相同 hash
# 常用于绕过签名验证

# 例: HMAC-SHA1 时序攻击
# 通过响应时间差异推断 HMAC 字节值
def hmac_timing_attack(message, key_length=32):
    recovered_key = b''
    for key_pos in range(key_length):
        for byte in range(256):
            k = recovered_key + bytes([byte]) + b'\x00' * (key_length - len(recovered_key) - 1)
            start = time.time()
            compute_hmac(k, message)
            elapsed = time.time() - start
            if elapsed > threshold:  # 时间异常
                recovered_key += bytes([byte])
                break
    return recovered_key
```

---

## 4. 随机数预测

### 4.1 MT19937 克隆

```python
import random

def clone_mt19937():
    """通过 624 个连续输出克隆 MT19937 PRNG"""
    # 获取 624 个连续随机数
    outputs = [random.getrandbits(32) for _ in range(624)]

    # 还原状态 (untemper)
    def untemper(y):
        # undo right shift by 18
        y = y << 18 | (y >> 14)
        # undo left shift by 15
        y = y >> 15 | (y << 17 & 0x80000000)
        # undo right shift by 7
        for _ in range(4):
            y = y >> 7 | (y << 25 & 0xFE000000)
        # undo right shift by 11
        y = y >> 11 | (y << 21 & 0x7FFE0000)
        return y

    mt_state = [untemper(output) for output in outputs]

    # 创建新的 MT19937 实例
    import random as r
    mt = r.Random()
    mt.setstate((3, tuple(mt_state), None))
    return mt
```

### 4.2 LCG 反推

```python
# LCG: next = (a * current + c) mod m
# 已知两个输出可反推 a, c

def solve_lcg(outputs, mod):
    """已知 LCG 输出序列, 求 a 和 c"""
    # outputs[i+1] = (a * outputs[i] + c) % mod
    # outputs[i+2] = (a * outputs[i+1] + c) % mod
    # 两式相减: a = (outputs[i+2] - outputs[i+1]) * inverse(outputs[i+1] - outputs[i], mod)

    diff1 = (outputs[1] - outputs[0]) % mod
    diff2 = (outputs[2] - outputs[1]) % mod
    a = (diff2 * inverse(diff1, mod)) % mod
    c = (outputs[1] - a * outputs[0]) % mod
    return a, c
```

### 4.3 弱随机种子

```python
# PHP mt_rand 默认用 time(0) 作种子
# 可预测: 遍历可能的时间戳

import datetime
import random

def predict_php_mt_rand(target_value, range_min, range_max):
    """预测 PHP mt_rand 输出"""
    now = datetime.datetime.now()
    for delta in range(-300, 300):  # 搜索时间范围
        seed = int(now.timestamp()) + delta
        random.seed(seed)
        # PHP: mt_rand(min, max) = min + (mt_rand() % (max-min+1))
        for _ in range(random.randint(224, 700)):  # mt_rand 内部调用次数不确定
            r = random.randint(range_min, range_max)
            if r == target_value:
                return seed
    return None
```

---

## 5. 工具清单

| 工具 | 说明 |
|------|------|
| CyberChef | 在线编码/解码 |
| SageMath | 数学计算/密码攻击 |
| GmpyC | Python 数论库 |
| PyCryptodome | Python 加密库 |
| RsaCtfTool | RSA 攻击工具 |
| hash_extender | 哈希长度扩展 |
| ophcrack | Windows 密码破解 |
| john the ripper | 密码哈希破解 |
| hashcat | GPU 密码破解 |
| Factordb | 因子数据库 |
| factordb-python | FactorDB API |