# 业务逻辑漏洞分析与修复报告

> **项目名称：** 用户信息管理平台（Flask User Login）
> **报告版本：** v4.0
> **报告日期：** 2026-07-09
> **报告人：** Claude Code (AI 辅助)
> **风险评估：** 🔴 严重（Critical）

---

## 📖 目录

- [一、执行摘要](#一执行摘要)
- [二、漏洞总览](#二漏洞总览)
- [三、漏洞详情](#三漏洞详情)
  - [VULN-201：IDOR 越权访问 — 任意用户资料查看](#vuln-201idor-越权访问--任意用户资料查看)
  - [VULN-202：未授权访问 — 敏感接口无登录校验](#vuln-202未授权访问--敏感接口无登录校验)
  - [VULN-203：负值充值 — 整数/金额操纵](#vuln-203负值充值--整数金额操纵)
  - [VULN-204：参数篡改 — 修改他人余额](#vuln-204参数篡改--修改他人余额)
- [四、修复前后对比](#四修复前后对比)
- [五、修复验证](#五修复验证)
- [六、安全建议](#六安全建议)
- [七、参考资料](#七参考资料)

---

## 一、执行摘要

### 概述

在本次安全审计中，对用户信息管理平台的**个人中心**和**充值**功能进行了全面的业务逻辑漏洞排查。业务逻辑漏洞不同于 SQL 注入等技术性漏洞，它们源于**应用逻辑设计缺陷**——代码按照开发者的意图正常执行，但业务规则本身存在安全缺失。

共发现 **4 个业务逻辑漏洞**，其中 **2 个严重级**、**2 个高危级**。

### 关键发现

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 4 |
| 严重（Critical） | 2 |
| 高危（High） | 2 |
| 已修复 | 4（100%） |

### 核心问题

| 漏洞 | 业务逻辑缺陷 | 攻击效果 |
|------|-------------|----------|
| IDOR 越权 | 未校验查看者身份 | 遍历 user_id 可看任意用户资料 |
| 未授权访问 | 未要求登录态 | 未登录也可访问敏感接口 |
| 负值充值 | 未校验金额正负 | 充负数直接扣光余额 |
| 参数篡改 | 信任前端提交的 user_id | 修改 user_id 给他人扣钱 |

### 攻击路径

```
攻击者 → 猜解 user_id=2 → 查看 alice 的资料（手机、余额）
攻击者 → 未登录 → 直接操作充值接口
攻击者 → 充负数 → 自己账户余额变为负数（实际是扣钱）
攻击者 → 修改充值表单的 user_id → 从他人账户扣钱
```

---

## 二、漏洞总览

### 漏洞清单

| 编号 | 漏洞类型 | OWASP 映射 | 风险 | 状态 |
|------|----------|------------|------|------|
| VULN-201 | IDOR 越权 — 水平权限绕过 | A01:2021-Broken Access Control | 🔴 严重 | ✅ 已修复 |
| VULN-202 | 未授权 — 敏感接口无登录校验 | A01:2021-Broken Access Control | 🔴 严重 | ✅ 已修复 |
| VULN-203 | 负值充值 — 业务规则绕过 | A04:2021-Insecure Design | 🟠 高危 | ✅ 已修复 |
| VULN-204 | 参数篡改 — 越权操作他人资产 | A01:2021-Broken Access Control | 🟠 高危 | ✅ 已修复 |

### 风险等级分布

```
严重 ████████████████████ 2  (50%)
高危 ████████████████████ 2  (50%)
```

---

## 三、漏洞详情

---

### VULN-201：IDOR 越权访问 — 任意用户资料查看

#### 基本信息

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-201 |
| 漏洞类型 | IDOR（Insecure Direct Object Reference）— 水平权限绕过 |
| OWASP 分类 | A01:2021 – Broken Access Control |
| CWE 编号 | CWE-639: Authorization Bypass Through User-Controlled Key |
| 风险等级 | 🔴 严重 |

#### 漏洞代码

```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")  # ← 用户可任意控制
    if not user_id:
        return render_template("profile.html", error="请提供用户 ID")

    user_info = get_user_by_id(user_id)  # ← 直接用 URL 参数查询
    if not user_info:
        return render_template("profile.html", error="用户不存在")

    return render_template("profile.html", user=user_info)
```

#### 根因分析

`user_id` 完全由 URL 查询参数控制，且**没有验证当前登录用户和所查询用户是否匹配**。攻击者只需要遍历 `user_id` 参数即可查看所有用户的个人信息。

| 请求 | 结果 |
|------|------|
| `/profile?user_id=1` | 查看 admin 的资料（邮箱、手机、余额） |
| `/profile?user_id=2` | 查看 alice 的资料 |
| `/profile?user_id=3` | 查看新注册用户的资料 |
| `/profile?user_id=999` | 提示"用户不存在"（信息泄露 — 确认 ID 是否存在） |

#### 影响分析

| 影响 | 说明 |
|------|------|
| 隐私泄露 | 任意用户的邮箱、手机号可被批量窃取 |
| 余额窥探 | 可监控高余额用户，作为后续攻击目标 |
| 信息枚举 | 通过遍历 ID 可获取平台用户总量 |

#### 修复方案

从 session 获取当前登录用户，不再信任 URL 参数：

```python
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_info = get_user_by_username(username)
    return render_template("profile.html", user=user_info)
```

---

### VULN-202：未授权访问 — 敏感接口无登录校验

#### 基本信息

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-202 |
| 漏洞类型 | 未授权访问（Missing Authentication） |
| CWE 编号 | CWE-306: Missing Authentication for Critical Function |
| 风险等级 | 🔴 严重 |

#### 漏洞代码

```python
@app.route("/profile")     # ← 无 @login_required，无 session 检查
def profile():
    user_id = request.args.get("user_id")
    ...

@app.route("/recharge", methods=["POST"])   # ← 同上
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    ...
```

#### 根因分析

`/profile` 和 `/recharge` 两个路由均未检查 `session` 中是否存在登录态。未登录用户可以：

1. 直接访问 `/profile?user_id=1` 查看任意用户资料
2. 直接 POST 到 `/recharge` 操作任意用户的余额

#### 攻击复现

```bash
# 未登录查看 admin 资料
curl "http://127.0.0.1:5000/profile?user_id=1"

# 未登录给 alice 充值 -1000（扣钱）
curl -X POST http://127.0.0.1:5000/recharge -d "user_id=2&amount=-1000"
```

#### 修复方案

```python
@app.route("/profile")
def profile():
    if "username" not in session:         # 新增登录检查
        return redirect("/login")
    ...

@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:         # 新增登录检查
        return redirect("/login")
    ...
```

---

### VULN-203：负值充值 — 业务规则绕过

#### 基本信息

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-203 |
| 漏洞类型 | 业务规则绕过（Business Logic Flaw） |
| CWE 编号 | CWE-841: Improper Enforcement of Behavioral Workflow |
| 风险等级 | 🟠 高危 |

#### 漏洞代码

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    amount = float(amount)

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?, (amount, user_id)")
    # ← amount 为负数时，balance = balance + (-99999) = 扣钱
```

#### 根因分析

代码将 `amount` 直接加到余额上，但未检查 `amount` 是否为正数。`balance + (-99999)` 等价于 `balance - 99999`。攻击者可以在充值接口中**提交负数**，实现盗刷余额。

#### 攻击复现

```bash
# 攻击者给自己充值 -99999，余额被扣光
curl -X POST http://127.0.0.1:5000/recharge \
  -d "user_id=1&amount=-99999"
```

#### 修复方案

```python
try:
    amount = float(amount)
except ValueError:
    return redirect("/profile")

if amount <= 0:                           # 新增正负校验
    return redirect("/profile?error=充值金额必须大于0")
```

---

### VULN-204：参数篡改 — 越权操作他人资产

#### 基本信息

| 属性 | 值 |
|------|----|
| 漏洞编号 | VULN-204 |
| 漏洞类型 | 参数篡改（Parameter Tampering） |
| CWE 编号 | CWE-472: External Control of Assumed-Immutable Web Parameter |
| 风险等级 | 🟠 高危 |

#### 漏洞代码

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")   # ← 信任前端传来的 user_id
    amount = request.form.get("amount")

    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    # 攻击者修改隐藏字段 user_id，可给任意用户扣钱或充值
```

```html
<!-- profile.html 中的隐藏字段 -->
<input type="hidden" name="user_id" value="1">
```

#### 根因分析

`user_id` 来自前端表单的隐藏字段，但**隐藏字段对用户不可见但可修改**。攻击者可以：

1. 用浏览器开发者工具修改隐藏字段的值
2. 直接构造 POST 请求指定任意 `user_id`
3. 给他人充负数 = 从他人账户盗刷余额

#### 攻击复现

```bash
# 攻击者登录后，修改隐藏字段 user_id=2，给 alice 充负数
curl -X POST http://127.0.0.1:5000/recharge \
  -b "session=攻击者的cookie" \
  -d "user_id=2&amount=-5000"            # ← 从 alice 扣 5000
```

#### 修复方案

不从表单获取 `user_id`，改用 session 中登录用户的 ID：

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_info = get_user_by_username(username)

    # 从数据库获取用户 ID，而非从前端获取
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
              (amount, user_info["id"]))
```

同时移除模板中的 `user_id` 隐藏字段。

---

## 四、修复前后对比

### profile() 完整对比

```diff
  @app.route("/profile")
  def profile():
-     user_id = request.args.get("user_id")
-     if not user_id:
-         return render_template("profile.html", error="请提供用户 ID")
-     user_info = get_user_by_id(user_id)
-     if not user_info:
-         return render_template("profile.html", error="用户不存在")
+     if "username" not in session:
+         return redirect("/login")
+     username = session["username"]
+     user_info = get_user_by_username(username)

      return render_template("profile.html", user=user_info)
```

### recharge() 完整对比

```diff
  @app.route("/recharge", methods=["POST"])
  def recharge():
+     if "username" not in session:
+         return redirect("/login")
+
-     user_id = request.form.get("user_id")
      amount = request.form.get("amount")
-     if not user_id or not amount:
-         return redirect("/")
      ...
+     if amount <= 0:
+         return redirect("/profile?error=充值金额必须大于0")

-     c.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
-               (amount, user_id))
+     username = session["username"]
+     user_info = get_user_by_username(username)
+     c.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
+               (amount, user_info["id"]))
```

### profile.html 对比

```diff
  <form method="POST" action="/recharge" class="search-form">
-     <input type="hidden" name="user_id" value="{{ user.id }}">
      <input type="number" name="amount" ...>
      <button type="submit">充值</button>
  </form>
```

---

## 五、修复验证

### 验证结果

| # | 测试用例 | 修复前 | 修复后 | 状态 |
|---|---------|--------|--------|------|
| 1 | 未登录访问 `/profile` | 正常返回用户资料 | 302 跳转到登录页 | ✅ |
| 2 | 未登录 POST `/recharge` | 正常扣款 | 302 跳转到登录页 | ✅ |
| 3 | admin 查看 alice 资料 `?user_id=2` | 返回 alice 的邮箱/手机 | 忽略 URL 参数，显示自己资料 | ✅ |
| 4 | 充负数 `amount=-99999` | 余额被扣光 | 提示"充值金额必须大于0" | ✅ |
| 5 | 充 0 `amount=0` | 余额不变（浪费请求） | 提示"充值金额必须大于0" | ✅ |
| 6 | 正常充值 `amount=+100` | 余额增加 100 | 余额增加 100 | ✅ |
| 7 | alice 登录，只能充自己账户 | 修改 user_id 可充他人 | 自动使用登录用户 ID | ✅ |

### 验证命令（可复现）

```bash
# 1. 越权访问 → 应跳转登录页
curl -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/profile
# 预期: 302

# 2. 越权充值 → 应跳转登录页
curl -X POST -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/recharge -d "amount=100"
# 预期: 302

# 3. 负数充值 → 应拒绝
curl -X POST -b cookies.txt -o /dev/null -w "%{redirect_url}" \
  http://127.0.0.1:5000/recharge -d "amount=-99999"
# 预期: ...error=充值金额必须大于0

# 4. 正常充值 → 应成功
curl -X POST -b cookies.txt http://127.0.0.1:5000/recharge -d "amount=100"
curl -b cookies.txt http://127.0.0.1:5000/profile | grep "¥"
# 预期: 余额增加了 100
```

---

## 六、安全建议

### 业务逻辑漏洞防御清单

| 原则 | 说明 |
|------|------|
| **永不信任客户端** | user_id 等重要参数必须从 session/服务端获取，而非 URL/表单 |
| **每个接口都要校验身份** | 敏感操作必须验证登录态，不能遗漏 |
| **服务端做最终校验** | 前端的 `min="0"` 只是用户体验，服务端必须重新校验 |
| **校验业务规则** | 金额必须 > 0、数量不能为负、状态转换必须合法 |
| **最小权限原则** | 用户只能操作自己的资源，系统管理员才能操作全局资源 |

### 本次已修复

| 优先级 | 措施 | 对应漏洞 |
|--------|------|----------|
| 🔴 P0 | profile 从 session 获取用户，不从 URL 参数 | VULN-201, VULN-202 |
| 🔴 P0 | recharge 校验登录态 | VULN-202 |
| 🔴 P0 | recharge 校验 amount > 0 | VULN-203 |
| 🔴 P0 | recharge 从 session 取 user_id，不从表单 | VULN-204 |

### 业务逻辑 vs 技术漏洞

```
技术漏洞（前三轮）：
  SQL 注入 → 输入未过滤 → 注入到 SQL 语句
  文件上传 → 文件未校验 → 恶意文件写入磁盘

业务逻辑漏洞（本轮）：
  IDOR 越权 → 代码正常执行，但权限规则缺失
  负值充值 → 代码正常执行，但业务规则未实施
  参数篡改 → 后端信任了前端参数
```

---

## 七、参考资料

| 来源 | 链接 |
|------|------|
| OWASP Top 10 2021 — A01 Broken Access Control | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| OWASP Authorization Bypass | https://owasp.org/www-community/attacks/Authorization_Bypass |
| CWE-639: Authorization Bypass Through User-Controlled Key | https://cwe.mitre.org/data/definitions/639.html |
| CWE-306: Missing Authentication | https://cwe.mitre.org/data/definitions/306.html |
| CWE-841: Business Logic Flaw | https://cwe.mitre.org/data/definitions/841.html |

---

*本报告由 Claude Code 自动生成，基于对项目源代码的静态分析和动态验证。*
*报告版本 v4.0 — 聚焦业务逻辑安全。*
