# 文件包含/路径遍历漏洞分析与修复报告

> **项目名称：** 用户信息管理平台（Flask User Login）
> **报告版本：** v5.0
> **报告日期：** 2026-07-10
> **报告人：** Claude Code (AI 辅助)
> **风险评估：** 🔴 严重（Critical）

---

## 📖 目录

- [一、执行摘要](#一执行摘要)
- [二、漏洞总览](#二漏洞总览)
- [三、漏洞详情](#三漏洞详情)
  - [VULN-301：路径遍历 — 任意文件读取](#vuln-301路径遍历--任意文件读取)
  - [VULN-302：源码泄露 — 敏感文件暴露](#vuln-302源码泄露--敏感文件暴露)
  - [VULN-303：数据库文件泄露](#vuln-303数据库文件泄露)
- [四、修复前后对比](#四修复前后对比)
- [五、修复验证](#五修复验证)
- [六、安全建议](#六安全建议)

---

## 一、执行摘要

### 概述

在本次安全审计中，对**动态页面加载功能**（`/page?name=xxx`）进行了全面的文件包含/路径遍历漏洞排查。该功能允许用户通过 URL 参数动态加载 `pages/` 目录下的页面文件，但**未对用户输入的路径做任何校验**，导致攻击者可利用 `../` 向上跳转读取服务器上的任意文件。

共发现 **3 个相关漏洞**，均为严重级。

### 关键发现

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 3 |
| 严重（Critical） | 3 |
| 已修复 | 3（100%） |

### 核心问题

```
用户输入 name = ../app.py
         ↓
os.path.join("pages", "../app.py")  →  "app.py"
         ↓
open("app.py").read()               →  返回源码
         ↓
渲染到页面显示
```

`os.path.join` 在面对 `../` 时不会阻止路径向上跳转。`os.path.join("pages", "../app.py")` 的结果是 `app.py`（等价于 `cd pages && cd ..`）。攻击者只需调整 `../` 的数量即可读取系统任意文件。

### 攻击路径

```
攻击者 → /page?name=../app.py              → 获取 Flask 源码（secret_key、数据库路径）
攻击者 → /page?name=../templates/login.html → 获取模板文件（调试信息中的管理员密码）
攻击者 → /page?name=../../etc/passwd        → 读取系统用户列表
攻击者 → /page?name=../data/users.db        → 下载 SQLite 数据库文件
```

---

## 二、漏洞总览

| 编号 | 漏洞类型 | OWASP 映射 | 风险 | 状态 |
|------|----------|------------|------|------|
| VULN-301 | 路径遍历 — 任意文件读取 | A01:2021-Broken Access Control | 🔴 严重 | ✅ 已修复 |
| VULN-302 | 源码泄露 — 应用代码暴露 | A05:2021-Security Misconfiguration | 🔴 严重 | ✅ 已修复 |
| VULN-303 | 数据库文件泄露 | A04:2021-Insecure Design | 🔴 严重 | ✅ 已修复 |

---

## 三、漏洞详情

### VULN-301：路径遍历 — 任意文件读取

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-301 |
| 漏洞类型 | 路径遍历（Path Traversal） |
| CWE 编号 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| 风险等级 | 🔴 严重 |

#### 漏洞代码

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    # 直接拼接，无任何校验
    page_path = os.path.join("pages", name)

    if os.path.exists(page_path):
        with open(page_path, "r") as f:
            page_content = f.read()
```

#### 根因分析

`os.path.join("pages", "../app.py")` 在 POSIX 系统上的结果为 `app.py`。`../` 抵消了 `pages/` 前缀，最终路径指向了项目根目录。攻击者只需要控制 `../` 的数量即可跳转到任意目录。

```python
os.path.join("pages", "help")              → "pages/help"           ✅ 正常
os.path.join("pages", "../app.py")         → "app.py"               ❌ 逃逸
os.path.join("pages", "../../etc/passwd")  → "../etc/passwd"        ❌ 逃逸
```

#### 攻击复现

```bash
# 读取 Flask 应用源码
curl "http://127.0.0.1:5000/page?name=../app.py"

# 读取系统密码文件
curl "http://127.0.0.1:5000/page?name=../../../../etc/passwd"

# 读取任意 HTML 模板
curl "http://127.0.0.1:5000/page?name=../templates/login.html"
```

#### 影响分析

| 影响 | 说明 |
|------|------|
| 源代码泄露 | `app.py` 中的 secret_key、数据库路径、业务逻辑完全暴露 |
| 系统文件读取 | `/etc/passwd` 等系统文件可被读取，辅助提权攻击 |
| 任意文件下载 | 配合已知路径可下载服务器上任何可读文件 |

---

### VULN-302：源码泄露 — 敏感信息暴露

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-302 |
| 漏洞类型 | 敏感信息泄露（Sensitive Information Exposure） |
| CWE 编号 | CWE-540: Information Exposure Through Source Code |
| 风险等级 | 🔴 严重 |

#### 漏洞说明

通过路径遍历读取 `app.py` 后，攻击者可获得以下敏感信息：

| 泄露信息 | 代码位置 | 用途 |
|----------|----------|------|
| `secret_key = "dev-key-2025"` | app.py:7 | 伪造任意用户的 session cookie |
| `data/users.db` | app.py:46 | SQLite 数据库路径 |
| `ALLOWED_EXTENSIONS` | app.py:11 | 文件上传白名单规则 |
| `MAX_CONTENT_LENGTH` | app.py:8 | 文件大小限制配置 |
| 全部路由和业务逻辑 | — | 发现更多攻击面 |

**危害：** 获取 `secret_key` 后，攻击者可伪造任意用户的 session cookie，无需密码即可登录任何账户：

```python
import jwt  # Flask 使用 itsdangerous，本质类似 JWT
# 伪造 admin 的 session cookie
fake_session = {"username": "admin"}
```

---

### VULN-303：数据库文件泄露

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-303 |
| 漏洞类型 | 数据库文件泄露 |
| CWE 编号 | CWE-312: Cleartext Storage of Sensitive Information |
| 风险等级 | 🔴 严重 |

#### 漏洞说明

`data/users.db` 是 SQLite 数据库文件，虽然密码已哈希，但仍然包含所有用户的邮箱、手机号、余额等敏感信息。通过路径遍历读取该文件后，攻击者可下载完整数据库。

```bash
# 读取 SQLite 数据库文件
curl "http://127.0.0.1:5000/page?name=../data/users.db" -o leaked.db
```

虽然密码已使用 Werkzeug 的 scrypt 哈希，但攻击者可离线进行暴力破解，且手机号、邮箱等明文信息直接泄露。

---

## 四、修复前后对比

### 修复方案

使用 `os.path.realpath()` 规范化路径，然后校验其是否以 `pages/` 目录为前缀：

```diff
  @app.route("/page")
  def dynamic_page():
      name = request.args.get("name", "")
      if not name:
          return render_template("index.html", page_error="请提供页面名称")

-     page_path = os.path.join("pages", name)
+     requested_path = os.path.join("pages", name)
+     real_path = os.path.realpath(requested_path)
+     pages_dir = os.path.realpath("pages")
+
+     if not real_path.startswith(pages_dir):
+         return render_template("index.html", page_error="页面不存在")

      page_content = None
-     if os.path.exists(page_path):
-         with open(page_path, "r", encoding="utf-8") as f:
+     if os.path.exists(real_path) and os.path.isfile(real_path):
+         with open(real_path, "r", encoding="utf-8") as f:
              page_content = f.read()
      else:
-         html_path = page_path + ".html"
-         if os.path.exists(html_path):
+         html_path = real_path + ".html"
+         if os.path.exists(html_path) and os.path.isfile(html_path):
              with open(html_path, "r", encoding="utf-8") as f:
                  page_content = f.read()
          else:
              return render_template("index.html", page_error="页面不存在")

      return render_template("index.html", page_content=page_content)
```

### 修复原理

| 步骤 | 说明 |
|------|------|
| `os.path.join("pages", name)` | 拼接得到原始请求路径 |
| `os.path.realpath()` | 解析所有 `../`，返回真实绝对路径 |
| `.startswith(pages_dir)` | 检查最终路径是否在 pages/ 范围内 |

#### 路径解析示例

| 用户输入 | `os.path.join` 结果 | `os.path.realpath` 结果 | 是否在 pages/ 内 |
|----------|--------------------|------------------------|----------------|
| `help` | `pages/help` | `/var/.../pages/help` | ✅ |
| `help.html` | `pages/help.html` | `/var/.../pages/help.html` | ✅ |
| `../app.py` | `app.py` | `/var/.../app.py` | ❌ 拦截 |
| `../../etc/passwd` | `../etc/passwd` | `/etc/passwd` | ❌ 拦截 |

---

## 五、修复验证

### 测试结果

| # | 测试用例 | 修复前 | 修复后 | 状态 |
|---|---------|--------|--------|------|
| 1 | `?name=help` | 正常显示帮助中心 | 正常显示帮助中心 | ✅ |
| 2 | `?name=../app.py` | 读取到 Flask 源码（含 secret_key） | 返回"页面不存在" | ✅ |
| 3 | `?name=../templates/login.html` | 读取到 HTML 模板 | 返回"页面不存在" | ✅ |
| 4 | `?name=../../../../etc/passwd` | 读取系统 passwd 文件 | 返回"页面不存在" | ✅ |
| 5 | `?name=../data/users.db` | 下载 SQLite 数据库 | 返回"页面不存在" | ✅ |
| 6 | `?name=notexist` | 返回"页面不存在" | 返回"页面不存在" | ✅ |

### 验证命令

```bash
# 正常页面 → 应返回内容
curl -s "http://127.0.0.1:5000/page?name=help" | grep "帮助中心"

# 路径遍历 → 应拦截
curl -s "http://127.0.0.1:5000/page?name=../app.py" | grep "页面不存在"

curl -s "http://127.0.0.1:5000/page?name=../templates/base.html" | grep "页面不存在"

curl -s "http://127.0.0.1:5000/page?name=../../../etc/passwd" | grep "页面不存在"
```

---

## 六、安全建议

### 路径遍历防御原则

| 原则 | 说明 |
|------|------|
| **限制路径范围** | 使用 `os.path.realpath()` 解析后检查是否在允许的目录内 |
| **拒绝 `../` 和 `\`** | 或使用白名单列表，只允许预定义的页面名称 |
| **避免直接读取用户路径** | 更好的方式是用 ID 映射到文件：`{1: "help", 2: "about"}` |
| **最小文件权限** | 应用只能读取需要读取的目录，使用操作系统权限限制 |

### 修复清单

| 优先级 | 措施 |
|--------|------|
| 🔴 P0 | `os.path.realpath()` 规范化路径 |
| 🔴 P0 | 检查路径是否以 `pages/` 目录为前缀 |
| 🟠 P1 | `os.path.isfile()` 确保只读取文件而非目录 |

### 路径遍历与其他漏洞的关联

```
路径遍历（VULN-301）
    ├── 读取 app.py → secret_key 泄露 → 伪造 Session → 任意账户登录
    ├── 读取 *.html → 模板源码 + 调试信息泄露
    ├── 读取 *.db   → 数据库泄露 → 用户信息批量窃取
    └── 读取 /etc/* → 系统信息 → 进一步提权攻击
```

---

## 参考资料

| 来源 | 链接 |
|------|------|
| CWE-22: Path Traversal | https://cwe.mitre.org/data/definitions/22.html |
| OWASP Path Traversal | https://owasp.org/www-community/attacks/Path_Traversal |
| OWASP File Inclusion | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion |

---

*本报告由 Claude Code 自动生成。*
*报告版本 v5.0 — 聚焦文件包含/路径遍历安全。*
