#!/usr/bin/env python3
"""
AWD Flag 加密保护工具
用途: 加密保护 flag 文件, 防止被攻击者读取
功能:
  1. 多种加密算法 (AES/XOR/Base64/自定义)
  2. 动态密钥 (基于时间/环境)
  3. 假 flag 诱饵
  4. 访问日志记录
  5. 一键部署到 Web 应用
"""

import os
import sys
import json
import base64
import hashlib
import random
import string
import time
import shutil
from datetime import datetime


class FlagProtector:
    def __init__(self, flag_file='/flag', backup_dir='/tmp/awd_flag_backup'):
        self.flag_file = flag_file
        self.backup_dir = backup_dir
        self.keys = {}
        os.makedirs(backup_dir, exist_ok=True)

    # ========= 1. 读取 Flag =========
    def read_flag(self):
        """读取原始 flag"""
        flag_paths = [
            self.flag_file,
            '/flag',
            '/flag.txt',
            '/root/flag',
            '/root/flag.txt',
            '/home/*/flag',
            '/var/www/html/flag',
            '/var/www/html/flag.txt',
            '/tmp/flag',
        ]

        for path in flag_paths:
            if '*' in path:
                # 通配符匹配
                import glob
                for p in glob.glob(path):
                    try:
                        content = open(p).read().strip()
                        if content:
                            print(f"  [+] 找到 flag: {p}")
                            return content, p
                    except Exception:
                        pass
            elif os.path.exists(path):
                try:
                    content = open(path).read().strip()
                    if content:
                        print(f"  [+] 找到 flag: {path}")
                        return content, path
                except Exception:
                    pass

        print("  [!] 未找到 flag 文件")
        return None, None

    # ========= 2. 加密方法 - AES =========
    def encrypt_aes(self, data, key=None):
        """AES 加密 (使用 cryptography 库)"""
        try:
            from cryptography.fernet import Fernet
            if key is None:
                key = Fernet.generate_key()
            elif isinstance(key, str):
                key = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())

            f = Fernet(key)
            encrypted = f.encrypt(data.encode())
            return {
                'method': 'aes',
                'encrypted': encrypted.decode(),
                'key': key.decode() if isinstance(key, bytes) else key,
            }
        except ImportError:
            print("  [!] 需要安装 cryptography: pip install cryptography")
            return self.encrypt_xor(data, key or 'default_key')

    def decrypt_aes(self, encrypted, key):
        """AES 解密"""
        try:
            from cryptography.fernet import Fernet
            if isinstance(key, str):
                key = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
            f = Fernet(key)
            return f.decrypt(encrypted.encode()).decode()
        except Exception:
            return f"解密失败: {e}"

    # ========= 3. 加密方法 - XOR =========
    def encrypt_xor(self, data, key=None):
        """XOR 加密"""
        if key is None:
            key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        key_bytes = key.encode() if isinstance(key, str) else key
        data_bytes = data.encode()

        encrypted = bytes([
            data_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data_bytes))
        ])

        return {
            'method': 'xor',
            'encrypted': base64.b64encode(encrypted).decode(),
            'key': key if isinstance(key, str) else key.decode(),
        }

    def decrypt_xor(self, encrypted_b64, key):
        """XOR 解密"""
        encrypted = base64.b64decode(encrypted_b64)
        key_bytes = key.encode() if isinstance(key, str) else key

        decrypted = bytes([
            encrypted[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(encrypted))
        ])
        return decrypted.decode()

    # ========= 4. 加密方法 - Base64 多层 =========
    def encrypt_base64(self, data, layers=5):
        """多层 Base64 编码"""
        result = data
        for _ in range(layers):
            result = base64.b64encode(result.encode()).decode()
        return {
            'method': 'base64',
            'encrypted': result,
            'key': str(layers),
        }

    def decrypt_base64(self, encrypted, layers):
        """多层 Base64 解码"""
        result = encrypted
        for _ in range(int(layers)):
            result = base64.b64decode(result).decode()
        return result

    # ========= 5. 加密方法 - 自定义混淆 =========
    def encrypt_obfuscate(self, data, key=None):
        """自定义混淆加密"""
        if key is None:
            key = hashlib.md5(str(time.time()).encode()).hexdigest()

        # 步骤1: 字符替换
        replace_map = {
            'a': '\x41', 'b': '\x42', 'c': '\x43', 'd': '\x44',
            'e': '\x45', 'f': '\x46', '0': '\x30', '1': '\x31',
            '2': '\x32', '3': '\x33', '4': '\x34', '5': '\x35',
        }
        step1 = ''
        for c in data:
            step1 += replace_map.get(c.lower(), c)

        # 步骤2: 反转
        step2 = step1[::-1]

        # 步骤3: XOR with key
        step3 = self.encrypt_xor(step2, key)

        # 步骤4: Base64
        step4 = base64.b64encode(step3['encrypted'].encode()).decode()

        return {
            'method': 'obfuscate',
            'encrypted': step4,
            'key': key,
        }

    def decrypt_obfuscate(self, encrypted_b64, key):
        """自定义混淆解密"""
        # 步骤4 反向: Base64 解码
        step3_encrypted = base64.b64decode(encrypted_b64).decode()

        # 步骤3 反向: XOR 解密
        step2 = self.decrypt_xor(step3_encrypted, key)

        # 步骤2 反向: 反转
        step1 = step2[::-1]

        # 步骤1 反向: 字符还原
        replace_map = {
            '\x41': 'a', '\x42': 'b', '\x43': 'c', '\x44': 'd',
            '\x45': 'e', '\x46': 'f', '\x30': '0', '\x31': '1',
            '\x32': '2', '\x33': '3', '\x34': '4', '\x35': '5',
        }
        original = ''
        i = 0
        while i < len(step1):
            if i + 1 < len(step1) and step1[i] in replace_map:
                original += replace_map[step1[i]]
            else:
                original += step1[i]
            i += 1

        return original

    # ========= 6. 动态密钥生成 =========
    def generate_dynamic_key(self, salt='awd2024'):
        """生成动态密钥 (基于时间)"""
        # 每小时变化
        hour_key = datetime.now().strftime('%Y%m%d%H')
        combined = f"{salt}_{hour_key}_{os.uname().nodename}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    # ========= 7. 创建假 Flag 诱饵 =========
    def create_decoy_flags(self, count=5):
        """创建假 flag 诱饵, 误导攻击者"""
        print(f"\n[*] 创建 {count} 个假 flag 诱饵")

        # 生成假 flag 格式
        flag_formats = [
            'flag{{{}}}',
            'FLAG{{{}}}',
            'ctf{{{}}}',
            'CTF{{{}}}',
            'awd{{{}}}',
        ]

        decoy_paths = [
            '/tmp/flag',
            '/tmp/flag.txt',
            '/var/tmp/flag',
            '/root/flag_decoy',
            '/home/ubuntu/flag',
            '/var/www/html/flag.txt',
            '/var/www/html/flag.php',
            '/var/www/html/.flag',
            '/opt/flag',
            '/etc/flag',
        ]

        created = []
        for i in range(min(count, len(decoy_paths))):
            try:
                # 生成假 flag 内容
                fake_content = random.choice(flag_formats).format(
                    ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
                )

                decoy_path = decoy_paths[i]
                with open(decoy_path, 'w') as f:
                    f.write(fake_content + '\n')

                # 设置诱饵文件权限
                os.chmod(decoy_path, 0o644)

                created.append(decoy_path)
                print(f"  [+] 诱饵: {decoy_path} -> {fake_content[:30]}...")

            except Exception:
                pass

        return created

    # ========= 8. 加密 Flag 文件 =========
    def protect_flag(self, method='aes'):
        """加密保护 flag 文件"""
        print(f"\n[*] 加密 flag (方法: {method})")

        flag_content, flag_path = self.read_flag()
        if not flag_content:
            print("  [!] 无法读取 flag")
            return False

        print(f"  [*] 原始 flag: {flag_content}")
        print(f"  [*] flag 路径: {flag_path}")

        # 备份原始 flag
        backup_path = os.path.join(self.backup_dir, f'flag_backup_{int(time.time())}')
        shutil.copy2(flag_path, backup_path)
        print(f"  [+] 已备份: {backup_path}")

        # 根据方法加密
        if method == 'aes':
            result = self.encrypt_aes(flag_content)
        elif method == 'xor':
            result = self.encrypt_xor(flag_content)
        elif method == 'base64':
            result = self.encrypt_base64(flag_content, layers=5)
        elif method == 'obfuscate':
            result = self.encrypt_obfuscate(flag_content)
        elif method == 'dynamic':
            # 动态密钥
            key = self.generate_dynamic_key()
            result = self.encrypt_aes(flag_content, key=key)
            result['method'] = 'dynamic_aes'
        else:
            print(f"  [!] 未知方法: {method}")
            return False

        # 保存密钥
        key_file = os.path.join(self.backup_dir, 'flag_key.json')
        self.keys[method] = result
        with open(key_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
        os.chmod(key_file, 0o600)

        # 写入加密后的 flag
        encrypted_content = f"""# AWD Protected Flag
# Method: {result['method']}
# Encrypted at: {datetime.now().isoformat()}
# DO NOT MODIFY - Use flag_protector.py to decrypt
{result['encrypted']}
"""
        with open(flag_path, 'w') as f:
            f.write(encrypted_content)

        # 修改权限
        os.chmod(flag_path, 0o644)

        print(f"  [+] Flag 已加密: {flag_path}")
        print(f"  [+] 密钥已保存: {key_file}")
        print(f"  [+] 加密内容: {result['encrypted'][:50]}...")

        return True

    # ========= 9. 解密 Flag =========
    def decrypt_flag(self, flag_path=None, key_file=None):
        """解密 flag"""
        print(f"\n[*] 解密 flag")

        if flag_path is None:
            flag_path = self.flag_file
        if key_file is None:
            key_file = os.path.join(self.backup_dir, 'flag_key.json')

        if not os.path.exists(flag_path):
            print(f"  [!] Flag 文件不存在: {flag_path}")
            return None

        if not os.path.exists(key_file):
            print(f"  [!] 密钥文件不存在: {key_file}")
            return None

        # 读取加密内容
        with open(flag_path, 'r') as f:
            content = f.read()

        # 提取加密数据 (跳过注释行)
        lines = [l for l in content.split('\n') if not l.startswith('#') and l.strip()]
        if not lines:
            print("  [!] 无加密数据")
            return None

        encrypted_data = lines[0].strip()

        # 读取密钥
        with open(key_file, 'r') as f:
            keys = json.load(f)

        # 尝试所有方法解密
        for method, key_info in keys.items():
            try:
                if method == 'aes' or method == 'dynamic_aes':
                    decrypted = self.decrypt_aes(encrypted_data, key_info['key'])
                elif method == 'xor':
                    decrypted = self.decrypt_xor(encrypted_data, key_info['key'])
                elif method == 'base64':
                    decrypted = self.decrypt_base64(encrypted_data, key_info['key'])
                elif method == 'obfuscate':
                    decrypted = self.decrypt_obfuscate(encrypted_data, key_info['key'])
                else:
                    continue

                if decrypted and not decrypted.startswith('解密失败'):
                    print(f"  [+] 解密成功 (方法: {method})")
                    print(f"  [+] Flag: {decrypted}")
                    return decrypted
            except Exception:
                continue

        print("  [!] 解密失败")
        return None

    # ========= 10. 生成 PHP Flag 读取器 =========
    def generate_php_flag_reader(self, output_path='/var/www/html/.secure_flag.php'):
        """生成 PHP 脚本用于安全读取 flag (部署在 Web 应用中)"""
        print(f"\n[*] 生成 PHP flag 读取器")

        # 读取当前 flag 并加密
        flag_content, _ = self.read_flag()
        if not flag_content:
            return False

        # 使用动态密钥加密
        key = self.generate_dynamic_key()
        encrypted = self.encrypt_xor(flag_content, key)

        # 生成 PHP 读取器
        php_code = f"""<?php
/**
 * AWD Flag 安全读取器
 * - 加密存储 flag
 * - 访问需要密钥
 * - 记录所有访问
 * 部署: 放置在 Web 目录, 通过特定参数访问
 */

class AWD_FlagReader {{
    private $encrypted = '{encrypted['encrypted']}';
    private $key = '{key}';
    private $access_log = '/tmp/awd_flag_access.log';
    private $valid_tokens = ['{hashlib.md5(b'awd_admin_token').hexdigest()}'];

    public function read($token = '') {{
        // 验证 token
        if (!in_array(md5($token), $this->valid_tokens)) {{
            $this->log_access('INVALID_TOKEN', $token);
            http_response_code(404);
            die('Not Found');
        }}

        // 记录访问
        $this->log_access('READ', $token);

        // 解密 flag
        $decrypted = $this->decrypt();
        return $decrypted;
    }}

    private function decrypt() {{
        $encrypted = base64_decode($this->encrypted);
        $key = $this->key;
        $result = '';
        for ($i = 0; $i < strlen($encrypted); $i++) {{
            $result .= $encrypted[$i] ^ $key[$i % strlen($key)];
        }}
        return $result;
    }}

    private function log_access($action, $token) {{
        $entry = json_encode([
            'time' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'action' => $action,
            'token_hash' => md5($token),
            'url' => $_SERVER['REQUEST_URI'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]) . "\\n";
        @file_put_contents($this->access_log, $entry, FILE_APPEND | LOCK_EX);
    }}
}}

// 使用: 访问 ?action=read_flag&token=awd_admin_token
if (isset($_GET['action']) && $_GET['action'] === 'read_flag') {{
    $reader = new AWD_FlagReader();
    $token = $_GET['token'] ?? '';
    $flag = $reader->read($token);
    if ($flag) {{
        header('Content-Type: text/plain');
        echo $flag;
    }}
}}
?>

<!-- AWD Secure Flag Reader -->
"""

        with open(output_path, 'w') as f:
            f.write(php_code)

        os.chmod(output_path, 0o644)
        print(f"  [+] PHP 读取器: {output_path}")
        print(f"  [+] 访问方式: ?action=read_flag&token=awd_admin_token")
        print(f"  [+] 访问日志: /tmp/awd_flag_access.log")

        return True

    # ========= 11. 监控 Flag 访问 =========
    def monitor_flag_access(self):
        """监控 flag 文件访问"""
        print(f"\n[*] 启动 flag 访问监控")

        # 使用 inotify 监控 (如果可用)
        monitor_script = f"""#!/bin/bash
# Flag 文件访问监控
FLAG_FILE="{self.flag_file}"
LOG_FILE="/tmp/awd_flag_monitor.log"

echo "[*] 监控 $FLAG_FILE ..." >> $LOG_FILE

# 使用 inotifywait 监控
if command -v inotifywait &> /dev/null; then
    inotifywait -m -e access,modify,attrib,close_write,open $FLAG_FILE |
    while read path action file; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $action - $(whoami) - $(ps -o comm= -p $PPID)" >> $LOG_FILE
    done
else
    # 后备方案: 定期检查
    while true; do
        md5=$(md5sum $FLAG_FILE | awk '{{print $1}}')
        if [ "$md5" != "$LAST_MD5" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - FLAG CHANGED: $md5" >> $LOG_FILE
            LAST_MD5=$md5
        fi
        sleep 1
    done
fi
"""
        monitor_path = '/tmp/awd_flag_monitor.sh'
        with open(monitor_path, 'w') as f:
            f.write(monitor_script)
        os.chmod(monitor_path, 0o755)

        # 后台运行
        import subprocess
        subprocess.Popen(['bash', monitor_path],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

        print(f"  [+] 监控已启动 (PID: 见 /tmp/awd_flag_monitor.log)")

    # ========= 12. 完整保护流程 =========
    def full_protect(self, method='aes', create_decoys=True, deploy_reader=True):
        """完整 flag 保护流程"""
        print("="*60)
        print("  AWD Flag 加密保护工具")
        print("="*60)

        # 1. 读取并备份 flag
        flag_content, _ = self.read_flag()
        if not flag_content:
            print("\n[!] 未找到 flag, 退出")
            return False

        # 2. 加密 flag
        self.protect_flag(method=method)

        # 3. 创建假 flag 诱饵
        if create_decoys:
            self.create_decoy_flags(count=8)

        # 4. 生成 PHP 读取器
        if deploy_reader:
            self.generate_php_flag_reader()

        # 5. 启动监控
        self.monitor_flag_access()

        # 汇总
        print("\n" + "="*60)
        print("  Flag 保护完成")
        print("="*60)
        print(f"  加密方法: {method}")
        print(f"  Flag 文件: {flag_path}")
        print(f"  备份位置: {self.backup_dir}")
        print(f"  PHP 读取器: /var/www/html/.secure_flag.php")
        print(f"  访问监控: /tmp/awd_flag_monitor.log")
        print(f"\n  解密命令:")
        print(f"    python3 flag_protector.py decrypt")

        return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 flag_protector.py protect [method]   # 加密保护 flag")
        print("  python3 flag_protector.py decrypt            # 解密 flag")
        print("  python3 flag_protector.py decoys [count]     # 创建假 flag")
        print("  python3 flag_protector.py reader             # 生成 PHP 读取器")
        print("  python3 flag_protector.py monitor            # 监控访问")
        print()
        print("加密方法 (method):")
        print("  aes       - AES 加密 (推荐, 需 cryptography)")
        print("  xor       - XOR 加密")
        print("  base64    - 多层 Base64")
        print("  obfuscate - 自定义混淆")
        print("  dynamic   - 动态密钥 AES")
        sys.exit(1)

    action = sys.argv[1]
    protector = FlagProtector()

    if action == 'protect':
        method = sys.argv[2] if len(sys.argv) > 2 else 'aes'
        protector.full_protect(method=method)
    elif action == 'decrypt':
        flag_path = sys.argv[2] if len(sys.argv) > 2 else None
        protector.decrypt_flag(flag_path=flag_path)
    elif action == 'decoys':
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        protector.create_decoy_flags(count=count)
    elif action == 'reader':
        protector.generate_php_flag_reader()
    elif action == 'monitor':
        protector.monitor_flag_access()
    else:
        print(f"未知操作: {action}")
