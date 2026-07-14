# 业务逻辑漏洞分析与修复报告（第二期）

> **项目名称：** 用户信息管理平台（Flask User Login）
> **报告版本：** v6.0
> **报告日期：** 2026-07-10
> **报告人：** Claude Code (AI 辅助)
> **风险评估：** 🔴 严重（Critical）

---

## 📖 目录

- [一、执行摘要](#一执行摘要)
- [二、漏洞总览](#二漏洞总览)
- [三、漏洞详情](#三漏洞详情)
  - [VULN-401：越权修改他人密码](#vuln-401越权修改他人密码)
  - [VULN-402：缺少原密码校验](#vuln-402缺少原密码校验)
  - [VULN-403：CSRF 跨站请求伪造](#vuln-403csrf-跨站请求伪造)
  - [VULN-404：参数篡改 — 隐藏字段 user_id](#vuln-404参数篡改--隐藏字段控制用户身份)
  - [VULN-405：弱密码与校验缺失](#vuln-405弱密码与校验缺失)
- [四、修复前后对比](#四修复前后对比)
- [五、修复验证](#五修复验证)
- [六、安全建议](#六安全建议)

---

## 一、执行摘要

在本次安全审计中，对**密码修改功能**、**充值功能**、**登录、注册、上传**共 5 个 POST 接口进行了全面的 CSRF 和业务逻辑漏洞排查。共发现 **7 个安全漏洞**，其中 **5 个严重级**、**2 个高危级**，已全部修复。

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 7 |
| 严重（Critical） | 5 |
| 高危（High） | 2 |
| 已修复 | 7（100%） |

### 攻击路径

```
攻击者 A（已登录）→ 修改密码接口 → 提交 username=admin → admin 密码被篡改 → 账户接管
攻击者 → 构造恶意页面 → 受害者登录后触发 CSRF → 改密/充值 → 账户接管
攻击者 → Login CSRF → 受害者登录攻击者账号 → 输入隐私信息 → 信息泄露
攻击者 → Register CSRF → 强制受害者注册账号 → 制造恶意行为记录
攻击者（已登录）→ 修改充值表单 user_id → 给他人充负数 → 盗刷余额
```

---

## 二、漏洞总览

| 编号 | 漏洞类型 | 风险 | 状态 |
|------|----------|------|------|
| VULN-401 | 越权修改他人密码 | 🔴 严重 | ✅ 已修复 |
| VULN-402 | 修改密码无原密码校验 | 🔴 严重 | ✅ 已修复 |
| VULN-403 | CSRF — 改密和充值接口 | 🔴 严重 | ✅ 已修复 |
| VULN-404 | CSRF — 登录接口（Login CSRF） | 🔴 严重 | ✅ 已修复 |
| VULN-405 | CSRF — 注册接口 | 🔴 严重 | ✅ 已修复 |
| VULN-406 | CSRF — 上传接口 | 🔴 严重 | ✅ 已修复 |
| VULN-407 | 参数篡改（充值 user_id） | 🟠 高危 | ✅ 已修复 |
| VULN-408 | 弱密码与校验缺失 | 🟠 高危 | ✅ 已修复 |

---

## 三、漏洞详情

### VULN-401：越权修改他人密码

| 属性 | 值 |
|------|----|
| 漏洞类型 | IDOR — 水平越权 |
| CWE 编号 | CWE-639: Authorization Bypass Through User-Controlled Key |
| 风险等级 | 🔴 严重 |

**漏洞代码：**
```python
username = request.form.get("username", "")  # 表单可控
c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, username))
```

**根因：** username 来自前端表单隐藏字段，攻击者可通过开发者工具修改该字段值为任意用户名，实现越权修改他人密码。

**修复：** 改为从 session 获取当前登录用户名，忽略表单中的 username 字段。

---

### VULN-402：缺少原密码校验

| 属性 | 值 |
|------|----|
| 漏洞类型 | 身份验证缺失 |
| CWE 编号 | CWE-306: Missing Authentication for Critical Function |
| 风险等级 | 🔴 严重 |

**漏洞代码：**
```python
# 只要登录就能改密码，无需知道原密码
new_password = request.form.get("new_password", "")
hashed_pw = generate_password_hash(new_password)
c.execute("UPDATE users SET password = ? WHERE username = ?", ...)
```

**根因：** 密码修改属于高风险操作，修改前应验证用户是否知道原密码。缺少此校验意味着只要攻击者短暂接触到已登录的设备，即可立即修改密码实现长期账户接管。

**修复：** 增加 `old_password` 字段校验，与数据库中的哈希进行比对。

---

### VULN-403 ~ VULN-406：CSRF 跨站请求伪造（全接口覆盖）

| 属性 | 值 |
|------|----|
| 漏洞类型 | CSRF — 跨站请求伪造 |
| CWE 编号 | CWE-352: Cross-Site Request Forgery |
| 风险等级 | 🔴 严重 |

**受影响接口（修复前全部无 CSRF 防护）：**

| 路由 | 触发方式 | CSRF 危害 |
|------|----------|----------|
| `/login` | POST 表单 | Login CSRF：强制用户登录攻击者账号，用户后续操作（充值、输手机号）泄露给攻击者 |
| `/register` | POST 表单 | 强制用户注册账号，制造恶意行为记录嫁祸用户 |
| `/upload` | POST multipart | 强制用户上传文件（需登录），但浏览器跨域限制较难携带文件内容 |
| `/recharge` | POST 表单 | 强制用户充值（需登录），盗刷余额 |
| `/change-password` | POST 表单 | 强制修改密码（需登录），账户被接管 |

**Login CSRF 攻击场景：**
```html
<!-- 攻击者构造恶意页面 → 受害者不知不觉登录了攻击者的账号 -->
<form action="http://victim.com/login" method="POST" id="f">
  <input type="hidden" name="_csrf_token" value="xxx">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="attacker123">
</form>
<script>document.getElementById('f').submit()</script>
```
受害者以为在操作自己的账号，实际在攻击者的账号下操作（如输入手机号、银行卡信息），攻击者登录自己账号即可查看。

**修复：** 所有 5 个 POST 接口统一使用 CSRF token 机制，每个表单生成唯一 token，提交时校验后销毁。

---

### VULN-404：参数篡改 — 充值 user_id

| 属性 | 值 |
|------|----|
| 漏洞类型 | 参数篡改 |
| CWE 编号 | CWE-472: External Control of Assumed-Immutable Web Parameter |
| 风险等级 | 🟠 高危 |

**漏洞代码（修复前）：**
```html
<input type="hidden" name="user_id" value="{{ user.id }}">
```
```python
user_id = request.form.get("user_id")  # 隐藏字段可控
```

**修复：** 充值 user_id 从 session 获取登录用户信息，移除前端隐藏字段，改为 session 数据源。

---

### VULN-405：弱密码与校验缺失

| 属性 | 值 |
|------|----|
| 漏洞类型 | 密码强度缺失 |
| CWE 编号 | CWE-521: Weak Password Requirements |
| 风险等级 | 🟠 高危 |

**问题：** 密码修改接口可设置任意长度密码（如 `12`），缺少密码强度校验和后端确认密码校验。

**修复：**
- 新密码长度 ≥ 6 位
- 确认密码两次输入必须一致
- 前后端双重校验

---

## 四、修复前后对比

### CSRF 防护全接口覆盖

| 路由 | 修复前 | 修复后 |
|------|--------|--------|
| `/login` | ❌ 无 CSRF | ✅ CSRF token 校验 |
| `/register` | ❌ 无 CSRF | ✅ CSRF token 校验 |
| `/upload` | ❌ 无 CSRF | ✅ CSRF token 校验 |
| `/recharge` | ❌ 无 CSRF | ✅ CSRF token 校验 |
| `/change-password` | ❌ 无 CSRF | ✅ CSRF token 校验 |

### change-password 完整对比

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 用户名来源 | 前端表单 hidden 字段 | session["username"] |
| 原密码校验 | ❌ 无 | ✅ check_password_hash |
| CSRF 防护 | ❌ 无 | ✅ Secret token 校验 |
| 确认密码校验 | 仅前端（可绕过） | 后端强制校验一致 |
| 密码强度 | 无限制 | 最少 6 位 |

### recharge 完整对比

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| user_id 来源 | 前端表单 hidden 字段 | session 取登录用户 ID |
| CSRF 防护 | ❌ 无 | ✅ Secret token 校验 |

---

## 五、修复验证

| # | 测试用例 | 修复前 | 修复后 | 状态 |
|---|---------|--------|--------|------|
| 1 | 修改他人密码（改 username 参数） | 成功篡改他人密码 | 从 session 取用户，不受表单影响 | ✅ |
| 2 | 原密码错误时改密 | 仍可改密 | 返回"原密码错误" | ✅ |
| 3 | 无 CSRF token 提交改密 | 成功改密 | 返回"表单已过期" | ✅ |
| 4 | 无 CSRF token 提交充值 | 成功充值 | 302 跳转并提示过期 | ✅ |
| 5 | 无 CSRF token 提交登录 | 正常登录 | 返回"表单已过期" | ✅ |
| 6 | 无 CSRF token 提交注册 | 正常注册 | 返回"表单已过期" | ✅ |
| 7 | 无 CSRF token 提交上传 | 正常上传 | 返回"表单已过期" | ✅ |
| 8 | 密码太短（3 位） | 成功设置弱密码 | 提示"不能少于 6 位" | ✅ |
| 9 | 两次密码不一致 | 仍可改密 | 提示"不一致" | ✅ |
| 10 | 正常改密+正常充值 | 正常 | 正常 | ✅ |

---

## 六、安全建议

| 优先级 | 措施 | 对应漏洞 |
|--------|------|----------|
| 🔴 P0 | 所有 5 个 POST 接口统一加入 CSRF token 校验 | VULN-403~406 |
| 🔴 P0 | 关键操作（改密、充值）从 session 取用户，不从表单 | VULN-401, VULN-407 |
| 🔴 P0 | 改密必须校验原密码 | VULN-402 |
| 🟠 P1 | 密码强度和确认密码后端校验 | VULN-408 |

---

*本报告由 Claude Code 自动生成。*
*报告版本 v6.0 — 聚焦修改密码与 CSRF 安全。*
