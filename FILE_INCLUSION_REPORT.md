# 文件包含漏洞分析与修复报告

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
  - [VULN-301：本地文件包含（LFI）— 路径遍历](#vuln-301本地文件包含lfi--路径遍历)
  - [VULN-302：本地文件包含（LFI）— 不安全渲染](#vuln-302本地文件包含lfi--不安全渲染)
  - [VULN-303：存储型 XSS — 上传 + 文件包含组合攻击](#vuln-303存储型-xss--上传--文件包含组合攻击)
- [四、修复前后对比](#四修复前后对比)
- [五、修复验证](#五修复验证)
- [六、安全建议](#六安全建议)

---

## 一、执行摘要

### 概述

在本次安全审计中，对**动态页面加载功能**（`/page?name=xxx`）进行了全面的文件包含漏洞排查。该功能允许用户通过 URL 参数动态加载 `pages/` 目录下的文件并渲染到页面上。

共发现 **3 个漏洞**，均为严重级。

### 关键发现

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 3 |
| 严重（Critical） | 3 |
| 已修复 | 3（100%） |

### 核心问题

| 漏洞 | 问题 | 危害 |
|------|------|------|
| 路径遍历 | `name` 未过滤 `../` | 读取服务器任意文件 |
| 不安全渲染 | `{{ page_content \| safe }}` | 文件中的 HTML/JS 在页面中执行 |
| 组合攻击 | 上传 HTML + 文件包含 | 上传的恶意 JS 在首页执行 |

### 什么是文件包含漏洞？

文件包含（File Inclusion）是指应用程序通过用户输入决定加载哪个文件并将其内容作为页面输出的一部分。与路径遍历（Path Traversal）的关键区别：

```
路径遍历：读取文件 → 下载/查看文件内容（仅读取）
文件包含：读取文件 → 渲染到页面中（读取 + 执行/展示）

文件包含 = 路径遍历 + 内容渲染
```

---

## 二、漏洞总览

| 编号 | 漏洞类型 | 风险 | 状态 |
|------|----------|------|------|
| VULN-301 | LFI — 路径遍历导致任意文件包含 | 🔴 严重 | ✅ 已修复 |
| VULN-302 | LFI — 不安全渲染导致 XSS | 🔴 严重 | ✅ 已修复 |
| VULN-303 | 上传 + 文件包含组合攻击 | 🔴 严重 | ✅ 已修复 |

---

## 三、漏洞详情

### VULN-301：本地文件包含（LFI）— 路径遍历

| 属性 | 值 |
|------|----|
| 漏洞类型 | 本地文件包含（Local File Inclusion） |
| CWE 编号 | CWE-98: Improper Control of Filename for Include/Require Statement |

#### 漏洞代码

```python
name = request.args.get("name", "")
page_path = os.path.join("pages", name)
# os.path.join("pages", "../app.py") → "app.py"  ← 直接逃逸
if os.path.exists(page_path):
    with open(page_path, "r") as f:
        page_content = f.read()
        # 内容传到模板渲染
```

#### 漏洞原理

`os.path.join("pages", "../app.py")` 的实际结果为 `app.py`，`../` 抵消了 `pages/` 前缀。攻击者可通过控制 `../` 数量读取系统任意文件并包含到页面中。

#### 攻击复现

```bash
# 包含 Flask 源码到页面中
curl "http://127.0.0.1:5000/page?name=../app.py"
# secret_key、数据库路径全部暴露在页面上

# 包含系统文件
curl "http://127.0.0.1:5000/page?name=../../../etc/passwd"
```

#### 修复方案

```python
requested_path = os.path.join("pages", name)
real_path = os.path.realpath(requested_path)
pages_dir = os.path.realpath("pages")

if not real_path.startswith(pages_dir):
    return render_template("index.html", page_error="页面不存在")
```

---

### VULN-302：本地文件包含（LFI）— 不安全渲染

| 属性 | 值 |
|------|----|
| 漏洞类型 | 本地文件包含 + 反射型 XSS |
| CWE 编号 | CWE-79: Improper Neutralization of Input During Web Page Generation |

#### 漏洞代码

```html
<!-- index.html -->
{% if page_content %}
    {{ page_content | safe }}    <!-- `| safe` 标记为安全HTML，不做转义 -->
{% endif %}
```

#### 漏洞原理

Jinja2 默认会对变量进行 HTML 转义（`<script>` → `&lt;script&gt;`），但 `| safe` 过滤器会**跳过转义**，将内容直接作为 HTML 渲染。如果包含的文件中含有 `<script>alert(1)</script>`，该脚本会在浏览器中执行。

即使路径遍历已修复，`pages/` 目录下的文件内容仍会被当做 HTML 渲染。如果攻击者能写入 `pages/` 目录（如配合其他漏洞），或在 `help.html` 中插入恶意代码，即可实现 XSS。

#### 攻击原理示意

```
用户访问 /page?name=help
         ↓
读取 pages/help.html → 内容含 <script>alert('XSS')</script>
         ↓
{{ page_content | safe }} → 原样输出 HTML，脚本执行
         ↓
浏览器弹窗 "XSS"
```

#### 修复方案

移除 `| safe` 过滤器，让 Jinja2 自动转义 HTML：

```html
<!-- 修复前 -->
{{ page_content | safe }}

<!-- 修复后 -->
{{ page_content }}
```

---

### VULN-303：存储型 XSS — 上传 + 文件包含组合攻击

| 属性 | 值 |
|------|----|
| 漏洞类型 | 存储型 XSS + 文件包含组合攻击 |
| CWE 编号 | CWE-79: Stored XSS |

#### 组合攻击链

这是文件包含漏洞最有威力的攻击方式——结合上传功能形成组合攻击链：

```
Step 1: 攻击者上传恶意 HTML 文件
         POST /upload → 保存到 static/uploads/evil.html
         evil.html 内容：<script>alert('XSS')</script>

Step 2: 攻击者通过文件包含加载该文件
         GET /page?name=../static/uploads/evil.html

Step 3: 恶意 HTML 在首页渲染，JS 脚本执行
         → XSS 发生在用户管理系统的域下
         → 可以窃取 session cookie、执行任意操作
```

#### 为什么简单路径遍历修复不能完全防御？

即使 `os.path.realpath()` 限制了文件范围，如果：
1. 攻击者上传一个 HTML 文件到 `static/uploads/`
2. 该目录在 `pages/` 同层或能被访问到
3. 通过路径遍历包含该文件 → 组合攻击

**但**如果路径遍历已修复（VULN-301），攻击者无法通过 `../` 访问到 `static/uploads/` 目录。所以 VULN-303 主要依赖于**不安全渲染**（VULN-302）的存在——即便只包含 `pages/` 内的文件，如果文件内容被攻击者控制，仍然存在风险。

---

## 四、修复前后对比

### 修复点 1：路径遍历 → 阻止逃逸出 pages/

```diff
  name = request.args.get("name", "")
- page_path = os.path.join("pages", name)
+ requested_path = os.path.join("pages", name)
+ real_path = os.path.realpath(requested_path)
+ pages_dir = os.path.realpath("pages")
+ if not real_path.startswith(pages_dir):
+     return render_template("index.html", page_error="页面不存在")
```

### 修复点 2：不安全渲染 → 移除 `| safe`

```diff
  {% if page_content %}
-     {{ page_content | safe }}
+     {{ page_content }}
  {% endif %}
```

### 修复点 3：帮助页面改为纯文本格式（可信内容示例）

```diff
- <h2>帮助中心</h2>
- <p>在登录页面输入用户名和密码即可登录。</p>
+ 帮助中心
+ ========
+ 在登录页面输入用户名和密码即可登录。
```

---

## 五、修复验证

### 测试结果

| # | 测试用例 | 修复前 | 修复后 | 状态 |
|---|---------|--------|--------|------|
| 1 | `?name=../app.py` 包含源码 | secret_key 暴露在页面上 | 返回"页面不存在" | ✅ |
| 2 | `?name=../templates/login.html` 包含模板 | 模板内容渲染到页面 | 返回"页面不存在" | ✅ |
| 3 | `?name=../../../etc/passwd` 包含系统文件 | 文件内容显示在页面 | 返回"页面不存在" | ✅ |
| 4 | `?name=help` 正常帮助页面 | 正常显示 HTML 格式化内容 | 正常显示纯文本内容 | ✅ |
| 5 | 包含含 `<script>` 的 HTML 文件 | 脚本在页面中执行 | 脚本被转义显示为文本 | ✅ |
| 6 | 上传 HTML 后通过 page 包含 | HTML 在首页渲染执行 | 路径遍历已拦截 | ✅ |

---

## 六、安全建议

### 文件包含 vs 路径遍历

```
文件包含漏洞 = 路径遍历 + 内容渲染

| 层面       | 防护措施                           |
|------------|-----------------------------------|
| 路径访问   | 限制可访问的目录范围               |
| 内容渲染   | 不要用 `| safe` 渲染不可信内容     |
| 输入来源   | 最好使用白名单 ID 映射文件路径     |
```

### 本次修复

| 优先级 | 措施 | 对应漏洞 |
|--------|------|----------|
| 🔴 P0 | `os.path.realpath()` + `startswith()` 限制目录 | VULN-301 |
| 🔴 P0 | 移除 `{{ page_content \| safe }}` | VULN-302 |
| 🔴 P0 | 组合攻击路径被切断 | VULN-303 |

---

## 参考资料

| 来源 | 链接 |
|------|------|
| CWE-98: Local File Inclusion | https://cwe.mitre.org/data/definitions/98.html |
| OWASP File Inclusion | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion |
| OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |

---

*本报告由 Claude Code 自动生成。*
*报告版本 v5.0 — 聚焦文件包含漏洞。*
