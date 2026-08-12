#!/usr/bin/env python3
"""
AWD 信息收集工具 - 自动扫描目标信息
用途: 在比赛开始时快速收集目标信息
"""

import nmap
import requests
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor


class AWDRecon:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}

    def quick_scan(self, target, ports='22,80,443,3306,6379,8080,8443'):
        """快速端口扫描"""
        print(f"[*] 扫描 {target} ...")
        try:
            self.nm.scan(target, ports, arguments='-sV -T4')
            if target in self.nm.all_hosts():
                self.results[target] = {
                    'ports': [],
                    'os': self.nm[target].get('osmatch', []),
                }
                for proto in self.nm[target].all_protocols():
                    for port in self.nm[target][proto]:
                        info = self.nm[target][proto][port]
                        self.results[target]['ports'].append({
                            'port': port,
                            'state': info['state'],
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'product': info.get('product', ''),
                        })
                        print(f"  [+] Port {port}: {info['state']} - {info.get('name', '?')}")
        except Exception as e:
            print(f"  [-] 扫描失败: {e}")

    def web_info(self, target):
        """收集 Web 服务信息"""
        protocols = ['http', 'https']
        for proto in protocols:
            url = f"{proto}://{target}"
            try:
                resp = requests.get(url, timeout=5, verify=False)
                print(f"  [+] {proto}://{target} - {resp.status_code}")
                print(f"      Headers: {dict(resp.headers)}")

                # 识别技术栈
                tech_stack = []
                headers = resp.headers
                if 'Server' in headers:
                    tech_stack.append(f"Server: {headers['Server']}")
                if 'X-Powered-By' in headers:
                    tech_stack.append(f"X-Powered-By: {headers['X-Powered-By']}")

                if tech_stack:
                    print(f"      Tech: {', '.join(tech_stack)}")

                self.results[target]['web'] = {
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'length': len(resp.text),
                }
            except requests.exceptions.SSLError:
                pass
            except Exception as e:
                print(f"  [-] {proto}://{target} 失败: {e}")

    def mysql_info(self, target):
        """MySQL 信息收集"""
        try:
            import pymysql
            passwords = ['root', '', 'root123', 'password', '123456', 'admin']
            for pwd in passwords:
                try:
                    conn = pymysql.connect(
                        host=target, port=3306,
                        user='root', password=pwd,
                        connect_timeout=3
                    )
                    print(f"  [+] MySQL root:{pwd} 登录成功!")
                    cursor = conn.cursor()
                    cursor.execute("SELECT VERSION()")
                    version = cursor.fetchone()
                    print(f"      Version: {version}")
                    conn.close()
                    self.results[target]['mysql'] = {
                        'password': pwd,
                        'version': str(version),
                    }
                    break
                except pymysql.err.OperationalError:
                    continue
        except ImportError:
            print("  [!] 需要安装 pymysql: pip install pymysql")
        except Exception as e:
            print(f"  [-] MySQL 连接失败: {e}")

    def scan_all(self, targets_file):
        """扫描所有目标"""
        with open(targets_file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        for target in targets:
            print(f"\n{'='*50}")
            print(f"[*] 目标: {target}")
            print('='*50)

            self.quick_scan(target)
            self.web_info(target)
            self.mysql_info(target)

            print()

        return self.results

    def save_results(self, output_file):
        """保存结果"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[*] 结果已保存到 {output_file}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 awd_recon.py <targets.txt>")
        sys.exit(1)

    recon = AWDRecon()
    results = recon.scan_all(sys.argv[1])
    recon.save_results('recon_results.json')
