# Reverse 攻防深度手册

## 1. 静态分析

### 1.1 基础流程

```bash
# 1. 文件类型识别
file binary
# ELF 32-bit/64-bit → Linux 可执行文件
# PE 32-bit/64-bit → Windows
# Mach-O → macOS/iOS
# 其他 → 可能是 .pyc/.pyo/.jar/.class

# 2. 基础信息提取
strings binary | head -50              # 提取字符串
nm -C binary                           # 导出符号
readelf -h binary                      # ELF 头信息
readelf -S binary                      # Section 信息
readelf -s binary                      # 符号表
objdump -d binary                      # 反汇编
objdump -t binary                      # 符号表

# 3. 安全机制检查
checksec binary
# 或: readelf -l binary | grep -i stack

# 4. 关键字符串搜索
strings binary | grep -i flag
strings binary | grep -i password
strings binary | grep -i key
strings binary | grep -i secret
strings binary | grep -i http
strings binary | grep -i error
strings binary | grep -i success
strings binary | grep -i valid
strings binary | grep -i correct
strings binary | grep -i wrong
strings binary | grep -i input

# 5. 导入库分析
readelf -d binary | grep NEEDED
objdump -p binary | grep "NEEDED"

# 6. Python 编译文件
python -c "import dis; import marshal; f=open('file.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"
# 或使用 pycdc / uncompyle6

# 7. Java 编译文件
# jad-gui / cfr / procyon
```

### 1.2 IDA Pro 分析技巧

```
# 快捷键
F5      → 反编译
F8      → 单步执行
F9      → 运行到光标
X       → 交叉引用
Y       → 重命名/加注释
;       → 添加注释
A       → 在光标处命名
N       → 命名地址
G       → 跳转到地址
P       → 函数起始
Alt+F2  → Python 脚本
Shift+F3 → 搜索字符串

# 关键分析步骤
1. 查看 main 函数 → 程序入口
2. 识别关键函数（加密/解密/校验）
3. 查找硬编码值（密钥、密码、flag）
4. 跟踪数据流（用户输入 → 校验 → 输出）
5. 识别算法模式（常见加密算法特征）

# 常见加密算法特征
# AES: S 盒 (0x63,0x7c,0x77,0x7b,0xf2...)
# DES: 初始置换表 IP
# RC4: 256 字节状态表初始化
# RSA: 大数运算、modpow
# Base64: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
# SHA: 魔数 0x5a827999, 0x6ed9eba1 等
# MD5: 魔数 0xd76aa478, 0xe8c7b756 等
```

### 1.3 算法识别特征

| 算法 | 特征 |
|------|------|
| **AES** | S-box 常量 (0x63→0x7c→0x77→0x7b...) |
| **DES** | IP 置换表、64 位分组、S 盒 (0xe,4xd,4x1...) |
| **RC4** | 256 字节循环初始化 `for(i=0;i<256;i++)S[i]=i` |
| **RSA** | 大数 modPow、Montgomery 乘法 |
| **SHA-1** | 魔数 0x5a827999、0x6ed9eba1 |
| **SHA-256** | 魔数 0x428a2f98、0x71374491 |
| **MD5** | 魔数 0xd76aa478、0xe8c7b756 |
| **Base64** | 标准 Base64 字母表 |
| **XOR** | `^` 操作 + 固定密钥 |
| **Caesar** | `+3` 或 `-3` 偏移 |
| **TEA/XTEA** | 轮函数、`sum` 累加 |
| **VMProtect** | VM 解释器、字节码 |

---

## 2. 动态调试

### 2.1 GDB + pwndbg 完整脚本

```gdb
# ~/.gdbinit
source /usr/share/pwndbg/gdbinit.py

# 启动调试
gdb ./binary
# 或: gdb -q ./binary

# 常用命令
run <args>          # 运行程序
break main          # 断在 main
break *0x401234     # 断在地址
break function      # 断在函数
info breakpoints    # 查看断点
delete              # 删除断点
disable             # 禁用断点

# 调试流程
1. break main → run
2. ni / si → 单步
3. info registers → 查看寄存器
4. x/20gx $rsp → 查看栈
5. x/20i $rip → 反汇编
6. print variable → 打印变量
7. backtrace / bt → 调用栈

# 条件断点
break *0x401234 if $rax == 0x31337
break function if strstr((char*)$rdi, "flag")

# 内存搜索
find /binary 0x400000 0x500000, "flag"
find 0x600000 0x700000, "password"

# 动态修改
set $rax = 0       # 修改寄存器
call function      # 调用函数
return             # 强制返回

# 脚本化调试
python3
import gdb
for i in range(10):
    gdb.execute("continue")
    print(f"Break hit {i}")
end
```

### 2.2 x64dbg (Windows)

```
常用快捷键:
F2      → 单步 (Step Over)
F7      → 步入 (Step Into)
F8      → 步过 (Step Over)
F9      → 运行/继续
F12     → 跳出 (Step Out)
G       → 跳转到地址
C       → 执行到光标
D       → 内存视图
E       → 编辑

常用断点:
- 条件断点: 右键条件
- 内存断点: 内存访问时触发
- 消息断点: Windows 消息触发
- 异常断点: 异常触发

Python 脚本:
plugincmd scriptload "script.py"
```

### 2.3 Frida 动态插桩

```javascript
// 常用脚本骨架
Java.perform(function() {
    // Hook 方法
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(password) {
        console.log("[*] checkPassword called with: " + password);
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        ));
        var result = this.checkPassword(password);
        console.log("[*] result: " + result);
        return result;
    };

    // Hook native 函数
    Interceptor.attach(Module.findExportByName(null, "strlen"), {
        onEnter: function(args) {
            console.log("[*] strlen(" + args[0].readCString() + ")");
        },
        onLeave: function(retval) {
            console.log("[*] return: " + retval);
        }
    });

    // 内存搜索
    var ranges = Process.enumerateRanges("r--");
    ranges.forEach(function(range) {
        try {
            var matches = Memory.scanSync(range.base, range.size, "46 4c 41 47"); // "FLAG"
            matches.forEach(function(m) {
                console.log("[+] Found at: " + m.address);
            });
        } catch(e) {}
    });

    // 绕过 SSL Pinning
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.verify.implementation = function() { return true; };
});
```

---

## 3. 脱壳

### 3.1 壳识别

```bash
# PE 壳识别
peid binary.exe
# 或 strings 搜索壳特征
strings binary.exe | grep -i "upx\|aspack\|vmprotect\|themida\|enigma"

# 常见壳
# UPX: 压缩可执行文件
# VMProtect: 虚拟机保护
# Themida: 商业保护
# Enigma: 压缩+加密
# ASPack: 压缩保护
# PyInstaller: Python 打包
# PyArmor: Python 混淆
# Nuitka: Python 编译为 C
```

### 3.2 脱壳方法

```bash
# UPX (最简单)
upx -d binary.exe
upx -d --best binary.exe   # 最佳压缩

# PyInstaller 脱壳
pyinstxtractor.py binary.exe
# → 输出: binary.exe_extracted/
# → 找到: PYZ-00.pyz
# → pycdc PYZ-00.pyz 或 uncompyle6

# PyArmor 脱壳
# 1. pyinstxtractor.py 提取
# 2. 查找 pytransform 模块
# 3. 修补 pytransform 导入
# 4. uncompyle6 反编译

# Py2/3 字节码反编译
# .pyc 文件:
python -c "import dis,marshal; f=open('file.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"
# 或: uncompyle6 file.pyc, pycdc file.pyc

# .jar 脱壳
# 直接解压: jar xf file.jar
# 反编译: cfr file.jar, procyon file.jar
```

### 3.3 通用脱壳流程

```
1. 用 PE 工具检测壳类型 (peid, Detect It Easy)
2. 运行程序 → 等待自解压完成
3. Dump 内存镜像
   - OllyDbg: 暂停 → 右键进程 → Dump
   - LordPE: PE Editor → Dump
4. 重建导入表
   - Import Reconstructor (ImpREC)
5. 修复 PE 结构
6. 分析脱壳后的代码
```

---

## 4. 反反调试

### 4.1 常见反调试技术

| 技术 | 方法 | 绕过 |
|------|------|------|
| `ptrace` | 检测 `ptrace(TRACEME)` 返回值 | Hook `ptrace` 始终返回 0 |
| `IsDebuggerPresent` | Windows API | 修改 PEB.BeingDebugged = 0 |
| `CheckRemoteDebuggerPresent` | Windows API | Hook 始终返回 FALSE |
| `NtQueryInformationProcess` | 查询调试器状态 | Hook 返回 ProcessDebugFlags=0 |
| 时间检测 | `rdtsc` 两次调用 → 时间差过大 | 使用 Hardware Breakpoint |
| 父进程检测 | 检查父进程名 | 修改 PEB |
| 注册表检测 | 检查调试器注册表键 | 修补注册表 |
| 异常调试 | 故意触发异常 | 让调试器不处理异常 |
| `GetThreadContext` | 检查 Trap Flag | 修改 Context |
| `BeingDebugged` | PEB.BeingDebugged = 1 | 设置为 0 |
| `NtGlobalFlag` | PEB.NtGlobalFlag != 0 | 设置为 0 |
| `TLS Callback` | TLS 回调在 main 前执行 | 修改 TLS 回调指针 |

### 4.2 Frida 绕过脚本

```javascript
// 通用反调试绕过
Java.perform(function() {
    // 1. Hook ptrace
    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });

    // 2. Hook IsDebuggerPresent
    if (Module.findExportByName("kernel32.dll", "IsDebuggerPresent")) {
        Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
            onLeave: function(retval) {
                retval.replace(0);
            }
        });
    }

    // 3. Hook CheckRemoteDebuggerPresent
    if (Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent")) {
        Interceptor.attach(Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent"), {
            onLeave: function(retval) {
                retval.replace(0);
            }
        });
    }

    // 4. Android 绕过
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() { return false; };

    // 5. 绕过 PTrace
    var System = Java.use("java.lang.System");
    System.getProperty.implementation = function(key) {
        if (key === "java.vm.info") return "";
        return this.getProperty(key);
    };

    // 6. 绕过时间检测
    var SystemClock = Java.use("android.os.SystemClock");
    SystemClock.elapsedRealtime.implementation = function() {
        return 0;
    };
});
```

### 4.3 x64dbg 绕过

```
# 修改 PEB
# 1. 查找 PEB 地址
# 2. 修改偏移:
#    BeingDebugged: offset 2 → 0
#    NtGlobalFlag: offset 0xBC → 0
#    NtGlobalFlag2: offset 0x188 → 0

# OllyDbg 脚本
# 断点在 IsDebuggerPresent
# 命令: mov eax, 0; ret
```