# AWD 攻防分类手册

> 按 Web / Pwn / Misc / Crypto / Reverse / Mobile / Blockchain 分类整理，覆盖攻击手段、防御措施、Payload 模板、工具清单。

## 分类索引

| 分类 | 文件 | 核心内容 |
|------|------|----------|
| **Web** | [web.md](web.md) | SQL注入/文件上传/文件包含/RCE/XSS/反序列化/SSRF/SSTI/**隐藏后门专题(显性Webshell/变量覆盖/条件竞争/不死马)**/**中间件漏洞(Redis未授权/SSH后门)**/**硬编码泄露** + 完整利用链 + WAF绕过对照表 + 三语言防御代码 |
| **Pwn** | [pwn.md](pwn.md) | 栈溢出/格式化字符串/堆利用/UAF/ROP/ret2xxx + pwntools完整模板 + checksec应对策略表 + gadget速查 |
| **Misc** | [misc.md](misc.md) | 流量分析/隐写术/取证分析/编码解码/协议分析 + Wireshark过滤手册 + Volatility命令集 + 隐写决策树 |
| **Crypto** | [crypto.md](crypto.md) | 对称/非对称攻击、哈希攻击、随机数预测 + SageMath/Python完整利用代码 |
| **Reverse** | [reverse.md](reverse.md) | 静态/动态调试/脱壳/反反调试 + GDB脚本 + Frida代码 |
| **Mobile** | [mobile.md](mobile.md) | Android/iOS逆向完整流程 + smali修改 + Hook脚本 |
| **Blockchain** | [blockchain.md](blockchain.md) | 智能合约漏洞 + 重入攻击 + Solidity代码示例 |

## 快速导航

```
遇到题目 → 判断类型 → 查阅对应分类文件 → 复制 Payload/代码直接使用
```

### 场景 → 分类映射

| AWD 常见场景 | 查阅文件 | 重点章节 |
|-------------|---------|---------|
| 打靶机 Web 漏洞 | [web.md](web.md) | RCE / 文件上传 / SQL注入 |
| 修自家 Web 应用 | [web.md](web.md) | 防御措施 / WAF规则 |
| **AWD 开局排查预埋后门** | [web.md §11](web.md#11-awd-专属隐藏后门专题) | 显性Webshell / 变量覆盖 / 条件竞争 / 不死马 |
| **不死马无法清除** | [web.md §11.4](web.md) | 重启 PHP-FPM / chattr +i / 竞争删除脚本 |
| **被植入 SSH 后门** | [web.md §12.2](web.md) | 软链接/Wrapper/PAM/authorized_keys 检测与清除 |
| **Redis 未授权打内网** | [web.md §12.1](web.md) | 写公钥 / 写Webshell / 主从复制 RCE |
| **源码硬编码弱密码** | [web.md §13](web.md) | db.php / Cookie Key / md5 弱哈希检测 |
| **/.git / www.zip 泄露** | [web.md §13.2](web.md) | 备份文件检测 + GitHack 还原 |
| Pwn 二进制漏洞 | [pwn.md](pwn.md) | checksec应对策略 / pwntools模板 |
| 内存取证题 | [misc.md](misc.md) | Volatility3 命令手册 |
| 流量分析题 | [misc.md](misc.md) | Wireshark 过滤表达式 |
| 隐写题 | [misc.md](misc.md) | 隐写检测决策树 |
| RSA/DES 题 | [crypto.md](crypto.md) | Wiener攻击 / Coppersmith |
| Android 逆向 | [mobile.md](mobile.md) | APK 分析流程 |
| 智能合约漏洞 | [blockchain.md](blockchain.md) | 重入攻击 / 重放攻击 |

## 配套资源

- **实战 Skill**: [`.trae/skills/awd-competition/SKILL.md`](../.trae/skills/awd-competition/SKILL.md) — 按阶段执行 AWD 攻防全流程
- **攻击脚本**: `attack/` 目录下的 Python 脚本
- **防御脚本**: `defense/` 目录下的 WAF、自动防御脚本
