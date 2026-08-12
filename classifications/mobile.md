# Mobile 攻防深度手册

## 1. Android 逆向

### 1.1 完整分析流程

```bash
# Step 1: APK 提取
apktool d app.apk -o output/
jadx-gui app.apk
# 或: jadx -d output app.apk

# Step 2: 分析 AndroidManifest.xml
cat output/AndroidManifest.xml
# 关注:
# - package 名
# - 权限
# - Activity/Service/Receiver
# - 导出组件 (exported="true")
# - 调试标记 (android:debuggable="true")

# Step 3: 分析 smali 代码
ls output/smali*/
# 搜索关键:
grep -r "Lflag" output/smali*/
grep -r "password" output/smali*/
grep -r "secret" output/smali*/
grep -r "\.dex" output/smali*/

# Step 4: 反编译 Java
# jadx-gui → 查看 Java 代码
# 重点关注:
# - 入口 Activity
# - 加密/解密算法
# - 网络请求
# - 本地存储 (SharedPreferences, SQLite)
# - 敏感操作 (getPackageInfo, getDeviceId)

# Step 5: Native SO 分析
# 提取 lib/*.so
file lib/*.so
# IDA Pro 分析 SO
# 导出函数、字符串引用

# Step 6: 运行时 Hook
adb install app.apk
adb logcat | grep -i flag
# Frida Hook

# Step 7: 数据提取
adb shell
cd /data/data/com.example.app/
# 需要 root 或 su
# 提取:
#   databases/ (SQLite)
#   shared_prefs/ (SharedPreferences)
#   files/ (文件存储)
#   cache/ (缓存)
```

### 1.2 Smali 常用操作

```smali
# smali 基础语法
# .method → 方法开始
# .end method → 方法结束
# invoke- → 调用方法
# const/ → 加载常量
# move- → 移动结果
# return- → 返回

# 常见操作
# 1. Hook 关键方法:
#    - 在方法入口插桩
#    - 打印参数和返回值

# 2. 绕过签名验证:
#    - 修改 checkSignature 方法返回 true

# 3. 绕过 Root 检测:
#    - 修改 checkRoot 方法返回 false

# 4. 调试启用:
#    - 移除 android:debuggable="false"
#    - 添加 <application android:debuggable="true">

# 5. 绕过 SSL Pinning:
#    - 修改 SSL 校验方法

# 示例: 修改 onCreate 打印 flag
# .method protected onCreate(Landroid/os/Bundle;)V
#     .locals 2
#     invoke-super {p0}, {p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
#     const-string v0, "FLAG"
#     invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
#     ...
# .end method
```

### 1.3 Frida Hook 常用脚本

```javascript
// 1. 通用 Hook 模板
Java.perform(function() {
    // 枚举所有类
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().indexOf("flag") !== -1 ||
                className.toLowerCase().indexOf("check") !== -1) {
                console.log("[*] Found class: " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration done");
        }
    });

    // 搜索字符串常量
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var cls = Java.use(className);
                var methods = cls.class.getDeclaredMethods();
                methods.forEach(function(m) {
                    var params = m.getParameterTypes().map(function(p) {
                        return p.getName();
                    });
                    console.log("  Method: " + m.getName() + "(" + params.join(", ") + ")");
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

// 2. Root 检测绕过
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };

    // 通用 Root 检测
    var classes = [
        "com.google.android.gms.common.GooglePlayServicesUtil",
        "com.android.server.pm.PackageManagerService"
    ];

    // Hook shell 命令
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        console.log("[*] exec: " + cmd);
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Bypassing root check");
            var process = this.exec("echo");
            return process;
        }
        return this.exec(cmd);
    };
});

// 3. SSL Pinning 绕过
Java.perform(function() {
    // OkHttp 3
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(host, certs) {
            console.log("[*] Bypassing SSL pinning for: " + host);
        };
    } catch(e) {
        console.log("[!] OkHttp3 not found: " + e);
    }

    // TrustManager 绕过
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.use("javax.net.ssl.TrustManager");

    // TrustAll 实现
    var TrustAll = Java.registerClass({
        name: "org.TrustAll",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(null, [TrustAll.$new()], null);
    SSLContext.getInstance = sslCtx;
});

// 4. 数据库提取
Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.rawQuery.implementation = function(sql, selection) {
        console.log("[*] SQL: " + sql);
        var cursor = this.rawQuery(sql, selection);
        // 遍历结果
        if (cursor.moveToFirst()) {
            do {
                var row = "";
                for (var i = 0; i < cursor.getColumnCount(); i++) {
                    row += cursor.getColumnName(i) + "=" + cursor.getString(i) + "; ";
                }
                console.log("[*] Row: " + row);
            } while (cursor.moveToNext());
        }
        return cursor;
    };
});

// 5. SharedPreferences 监控
Java.perform(function() {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.implementation = function(key, defValue) {
        console.log("[*] SharedPreferences.get: " + key);
        return this.getString(key, defValue);
    };
    SharedPreferences.putString.implementation = function(key, value) {
        console.log("[*] SharedPreferences.put: " + key + " = " + value);
        this.edit().putString(key, value).commit();
    };
});
```

### 1.4 ADB 常用命令

```bash
# 设备管理
adb devices                    # 列出设备
adb -s SERIAL shell             # 指定设备
adb -s SERIAL install app.apk   # 安装
adb -s SERIAL uninstall pkg     # 卸载

# Shell 操作
adb shell                       # 进入 shell
adb shell su -c "command"       # root 执行

# 数据提取
adb pull /data/data/pkg/ /local/path/
adb push /local /remote

# 日志
adb logcat -c                   # 清空日志
adb logcat | grep -i flag       # 过滤 flag
adb logcat -s "System.err"      # 错误日志

# 进程
adb shell ps                    # 进程列表
adb shell pidof pkg             # PID

# 调试
adb shell am start -n pkg/activity  # 启动 Activity
adb shell dumpsys activity top     # 当前 Activity
adb shell dumpsys package pkg      # 包信息
adb shell dumpsys dbinfo pkg       # 数据库信息
adb shell dumpsys activity activities  # 所有 Activity

# 网络
adb reverse tcp:8080 tcp:8080    # 端口转发
adb forward tcp:8080 tcp:8080
adb shell netstat                # 网络状态
adb shell ip addr show wlan0     # WiFi IP
adb shell cat /proc/net/tcp      # TCP 连接

# 备份
adb backup -f backup.ab -apk -shared -all -system
# 恢复: adb restore backup.ab
```

---

## 2. iOS 逆向

### 2.1 分析流程

```bash
# Step 1: .ipa 提取
mkdir ipa_extract && cd ipa_extract
unzip app.ipa
# → Payload/Payload.app/

# Step 2: Mach-O 分析
file Payload.app/AppExecutable
# Mach-O 64-bit

# Step 3: class-dump 提取类信息
class-dump -H -o headers/ Payload.app/AppExecutable
# → 生成 .h 头文件
cat headers/*.h

# Step 4: Hopper/Ghidra 反编译
# Hopper: File → Open → AppExecutable
# Ghidra: File → Import File

# Step 5: 动态调试 (需要越狱或 Frida)
# Frida:
frida -n AppName -l script.js
frida -f bundle.id -l script.js

# Step 6: Keychain 提取
# 越狱设备:
security find-generic-password -a "AppName"
# 或: keychain-dump

# Step 7: 数据提取
# .app/ 内:
ls Payload.app/
# Documents/, Library/, tmp/
# SQLCipher 数据库:
# 需要密钥 (Hook 获取)
```

### 2.2 常用工具

| 工具 | 说明 |
|------|------|
| Hopper | macOS 反编译 |
| Ghidra | 开源反编译 |
| class-dump | 提取 Objective-C 类信息 |
| class-dump-z | class-dump 的增强版 |
| Frida | 动态插桩 |
| Cycript | 运行时注入 |
| idb | iOS 调试工具 |
| radare2 | 命令行逆向 |
| otool | Mach-O 工具 |
| lldb | macOS/iOS 调试 |
| strings | 字符串提取 |
| lipo | 架构合并 |

### 2.3 Frida iOS Hook 脚本

```javascript
// iOS 通用模板
if (ObjC.available) {
    // 枚举类
    var classes = ObjC.classes;
    Object.keys(classes).forEach(function(cls) {
        if (cls.toLowerCase().indexOf("flag") !== -1) {
            console.log("[*] Found class: " + cls);
            var methods = classes[cls].ownMethods;
            methods.forEach(function(m) {
                console.log("  Method: " + m);
            });
        }
    });

    // Hook 方法
    var ViewController = ObjC.classes.ViewController;
    ViewController["- checkPassword:"].implementation = function(password) {
        console.log("[*] checkPassword: " + password);
        var result = this["- checkPassword:"](password);
        console.log("[*] result: " + result);
        return result;
    };

    // Hook NSUserDefaults
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    NSUserDefaults["- objectForKey:"].implementation = function(key) {
        console.log("[*] UserDefaults[" + key + "]");
        return this["- objectForKey:"](key);
    };

    // Hook 网络请求
    var NSURLSession = ObjC.classes.NSURLSession;
    NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation = function(request, handler) {
        console.log("[*] Request: " + request.HTTPMethod() + " " + request.URL().absoluteString());
        return this["- dataTaskWithRequest:completionHandler:"](request, handler);
    };

    // Hook Keychain
    var Security = Module.findExportByName("Security", "SecurityItemCopyMatching");
    if (Security) {
        Interceptor.attach(Security, {
            onEnter: function(args) {
                console.log("[*] SecurityItemCopyMatching");
            }
        });
    }
}
```

### 2.4 脱越狱环境分析

```bash
# 越狱检测绕过
# 1. 修改 Info.plist
#    添加: <key>UIFileSharingEnabled</key><true/>
#    添加: <key>LSApplicationQueriesSchemes</key>

# 2. Frida 脚本绕过
if (ObjC.available) {
    var jailbreakCheck = ObjC.classes.JailbreakCheck;
    jailbreakCheck["+ isJailbroken"].implementation = function() { return 0; };
}

# 3. 检查越狱标志
#    /Cydia/
#    /Sbin/Sshd/
#    /Library/MobileSubstrate/
#    cydia:// URL scheme
```