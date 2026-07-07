# 安全漏洞修复报告

## Flask 用户管理系统 — 安全漏洞分析与修复

---

## 一、项目概述

本项目是一个基于 Python Flask 框架的简易用户信息管理平台，包含登录、注册、用户信息展示、登出等基本功能。本次作业的目标是：**识别代码中的安全漏洞，并逐一修复**，同时从架构层面提升项目的整体安全性。

### 项目结构（修复后）

```
flask-user-login/
├── app.py                  # Flask 主应用（路由、认证、配置）
├── requirements.txt        # Python 依赖清单
├── .gitignore              # Git 忽略规则
├── README.md               # 项目说明文档
├── templates/
│   ├── base.html           # 基础模板
│   ├── login.html          # 登录页面
│   ├── register.html       # 注册页面
│   ├── index.html          # 首页（用户信息展示）
│   └── error.html          # 404/429/500 错误页面
└── static/css/
    └── style.css           # 全局样式
```

---

## 二、环境与工具

| 项目 | 说明 |
|------|------|
| 操作系统 | Kali Linux 2026.1 (远程 SSH) |
| Web 框架 | Python Flask |
| 密码哈希 | Werkzeug (`generate_password_hash` / `check_password_hash`) |
| 速率限制 | Flask-Limiter |
| 测试工具 | curl / Burp Suite |
| 部署地址 | `http://192.168.81.132:5000` |

---

## 三、原始漏洞分析

### 漏洞 1：密码明文存储

**问题代码（`app.py`）：**

```python
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",      # ← 明文存储！
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",     # ← 明文存储！
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}
```

**危害：** 如果数据库文件被泄露（或攻击者通过其他漏洞获取了 USERS 字典的内容），所有用户的密码将以可读形式直接暴露。

**验证方式：** 查看源代码即可看到所有账号密码。

---

### 漏洞 2：密码明文比对

**问题代码（`app.py`）：**

```python
if username in USERS and USERS[username]["password"] == password:
```

**危害：** 使用 `==` 直接比字符串，不仅不安全（无法防御时序攻击），而且意味着密码必须明文存储才能比对。

**验证方式：** 查看登录逻辑代码，确认使用 `==` 直接比较。

---

### 漏洞 3：密码显示在页面上

**问题代码（`templates/index.html`）：**

```html
<tr>
    <td class="info-label">密码</td>
    <td class="info-value">{{ user.password }}</td>
</tr>
```

**危害：** 登录成功后，用户的密码直接渲染在网页上。如果用户离开电脑未锁屏，路过的人可直接看到密码。浏览器保存的页面源码中也包含密码。

**验证方式：** 登录后页面直接显示密码字段。

---

### 漏洞 4：HTML 注释泄露默认账号

**问题代码（`templates/login.html`）：**

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**危害：** 任何查看网页源代码的人都能直接获得管理员账号密码。攻击者不需要进行任何爆破或猜测。

**验证方式：** 浏览器右键 → 查看页面源代码，即可看到注释中的账号密码。

---

### 漏洞 5：弱 Secret Key

**问题代码（`app.py`）：**

```python
app.secret_key = "dev-key-2025"
```

**危害：** `secret_key` 用于 Flask 签名 session cookie。使用硬编码的弱密钥，攻击者可以伪造任意用户的 session，实现**会话劫持**和**身份伪造**。

**验证方式：** 使用 `flask-unsign` 工具可用该密钥伪造 session cookie。

---

### 漏洞 6：Debug 模式开启

**问题代码（`app.py`）：**

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

**危害：** Flask 的 debug 模式会在代码出错时显示详细的调试页面，包含源代码片段、环境变量、当前变量值等敏感信息。生产环境中绝对不应开启。

---

### 漏洞 7：无统一登录验证

**问题代码（`app.py`）：**

```python
@app.route("/")
def index():
    username = session.get("username")
    # 每个路由都要手动写这段检查，容易遗漏
```

**危害：** 每个受保护的路由都需要写重复的 session 检查逻辑，新增路由时容易遗忘，导致未授权访问。

---

### 漏洞 8：无爆破防护

**危害：** 没有登录失败次数限制，攻击者可以使用 Hydra 等工具对账号进行**无限次密码爆破**，直到猜中为止。

---

### 漏洞 9：无 CSRF 防护

**问题代码（`templates/login.html`）：**

```html
<form method="POST" action="/login">
    <!-- 没有 CSRF Token -->
```

**危害：** 攻击者可以构造恶意页面，诱导已登录用户的浏览器向本系统发送 POST 请求，执行非用户意愿的操作。

---

### 漏洞 10：密码强度不足

**问题代码（`app.py`）：**

```python
elif len(password) < 6:
    error = "密码长度不能少于 6 位。"
```

**危害：** 6 位的纯数字密码可以在极短时间内被暴力破解完成。

---

### 漏洞 11：无 Session 超时

**危害：** 用户登录后 session 永不过期。在公共电脑上，其他用户可以复用未过期的 session，无需密码即可登录。

---

### 漏洞 12：缺少安全响应头

**危害：** 没有设置安全相关的 HTTP 响应头，存在 clickjacking（点击劫持）、MIME 嗅探攻击等风险。

---

## 四、修复方案

### 修复 1：使用 Werkzeug 进行密码哈希存储

**修复思路：** 不存储明文密码，而是存储密码的哈希值。验证时用同样的哈希算法比对。

**修复后代码（`app.py`）：**

```python
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),  # ← 哈希存储
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"), # ← 哈希存储
    }
}
```

**效果：** 数据库中存储的是类似 `pbkdf2:sha256:600000$salt$hash` 的哈希值，即使数据泄露也无法还原出原始密码。

---

### 修复 2：使用 check_password_hash 进行密码验证

**修复后代码（`app.py`）：**

```python
# 修复前
if USERS[username]["password"] == password:

# 修复后
if check_password_hash(USERS[username]["password"], password):
```

**效果：** 使用 Werkzeug 提供的安全比对函数，防止时序攻击，同时兼容哈希存储。

---

### 修复 3：不在模板中输出密码

**修复后代码（`templates/index.html`）：**

```html
<!-- 密码行已删除 -->
```

同时在 `app.py` 中过滤掉密码字段：

```python
def get_safe_user(username):
    """获取不包含密码字段的用户信息。"""
    user = USERS.get(username)
    if user:
        return {k: v for k, v in user.items() if k != "password"}
    return None
```

**效果：** 密码不再出现在任何页面上，即使查看页面源代码或浏览器历史也无法看到密码。

---

### 修复 4：删除泄露信息的 HTML 注释

**修复后代码（`templates/login.html`）：**

```html
<!-- 调试信息：默认账号请在部署后修改密码 -->
```

**效果：** 查看网页源代码也无法获得管理员密码。

---

### 修复 5：Secret Key 从环境变量读取

**修复思路：** 不硬编码密钥，改为从环境变量读取。如果未设置则拒绝启动，防止使用弱密钥。

**修复后代码（`app.py`）：**

```python
import os

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "严重安全错误：必须设置环境变量 SECRET_KEY。\n"
        "   export SECRET_KEY=\"your-strong-secret-key-here\""
    )
```

**效果：** 密钥由运维人员部署时设置，每次部署可以不同。即使源码泄露，攻击者也无法伪造 session cookie。

---

### 修复 6：通过环境变量控制 Debug 模式

**修复后代码（`app.py`）：**

```python
debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
app.run(debug=debug_mode, host="0.0.0.0", port=5000)
```

**效果：** 生产环境默认关闭 debug，调试时设 `FLASK_DEBUG=1` 开启。防止生产环境暴露敏感信息。

---

### 修复 7：添加统一登录验证装饰器

**修复后代码（`app.py`）：**

```python
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@login_required       # ← 一键保护
def index():
    ...
```

**效果：** 新增受保护路由时只需添加 `@login_required` 注解，不会遗漏。

---

### 修复 8：添加爆破防护（速率限制 + 账户锁定）

**修复思路：** 从两个层面防护：1) 限制单 IP 的请求频率；2) 连续失败的账户临时锁定。

**修复后代码（`app.py`）：**

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app)

# 登录路由添加速率限制
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    ...

# 账户锁定机制
LOGIN_FAILURES = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

def is_account_locked(username):
    if username in LOGIN_FAILURES:
        attempts, lock_time = LOGIN_FAILURES[username]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            elapsed = (time.time() - lock_time) / 60
            if elapsed < LOGIN_LOCKOUT_MINUTES:
                return True, int(LOGIN_LOCKOUT_MINUTES - elapsed)
            else:
                del LOGIN_FAILURES[username]
    return False, 0
```

**效果：** 单 IP 每分钟仅允许 10 次 POST 请求；同一账户连续 5 次失败后锁定 15 分钟，爆破不可行。

---

### 修复 9：添加 CSRF 防护

**修复思路：** 使用 `secrets.token_hex(32)` 生成随机 Token，存入 session。表单中嵌入隐藏字段，POST 时校验。

**修复后代码（`app.py` + `login.html`）：**

```python
import secrets

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token(token):
    stored = session.pop("_csrf_token", None)
    return stored and token == stored
```

```html
<!-- login.html -->
<input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
```

**效果：** 攻击者无法伪造有效的 POST 请求，CSRF 攻击被有效防御。

---

### 修复 10：增强密码强度策略

**修复后代码（`app.py`）：**

```python
import re

def validate_password_strength(password):
    if len(password) < 8:
        return "密码长度不能少于 8 位。"
    if not re.search(r"[A-Z]", password):
        return "密码必须包含至少一个大写字母。"
    if not re.search(r"[a-z]", password):
        return "密码必须包含至少一个小写字母。"
    if not re.search(r"\d", password):
        return "密码必须包含至少一个数字。"
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{}|;:',.<>?/~`]", password):
        return "密码必须包含至少一个特殊字符。"
    return None
```

**效果：** 用户设置的密码强度显著提升，暴力破解难度大幅增加。

---

### 修复 11：添加 Session 超时机制

**修复后代码（`app.py`）：**

```python
from datetime import timedelta

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# 登录成功时
session.clear()          # Session Fixation 防护
session.permanent = True # 启用超时
session["username"] = username
```

**效果：** 用户登录 2 小时后 session 自动过期，需重新登录。公共电脑上的安全风险降低。

---

### 修复 12：添加安全响应头

**修复后代码（`app.py`）：**

```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

**效果：** 所有 HTTP 响应自动携带安全头部，防止点击劫持、MIME 嗅探、XSS 等攻击。

---

## 五、修复前后对比

| 漏洞项 | 修复前 | 修复后 |
|--------|--------|--------|
| 密码存储 | 明文 `"admin123"` | 哈希 `pbkdf2:sha256:...` |
| 密码比对 | `==` 字符串直接比 | `check_password_hash()` |
| 密码显示 | 页面上显示密码 | 密码不再出现在任何页面 |
| 默认账号泄露 | HTML 注释中写死 | 删除注释 |
| Secret Key | 硬编码 `"dev-key-2025"` | 环境变量读取，无回退 |
| Debug 模式 | 开启 `debug=True` | 环境变量控制，默认关闭 |
| 登录验证 | 每个路由手动检查 | `@login_required` 装饰器 |
| 爆破防护 | 无限制 | 10次/分钟 + 5次失败锁定15分钟 |
| CSRF 防护 | 无 | Token 生成 + 校验 |
| 密码强度 | ≥ 6 位 | ≥ 8 位 + 大写 + 小写 + 数字 + 特殊字符 |
| Session 超时 | 永不过期 | 2 小时自动过期 |
| 安全响应头 | 无 | CSP / X-Frame-Options / X-Content-Type-Options 等 6 项 |
| 登录 URL | 硬编码字符串 | `url_for()` 动态生成 |
| 代码重复 | 过滤密码写了两次 | 提取 `get_safe_user()` 函数 |
| 错误页面 | Flask 默认页 | 自定义 404/429/500 页面 |
| 用户注册 | 不支持 | 支持注册 + 密码强度校验 |
| 响应式设计 | 不支持手机 | 媒体查询适配移动端 |
| 操作日志 | 无 | 登录/登出/注册全流程记录 |

---

## 六、测试验证

### 修复后测试步骤

1. **启动服务**
   ```bash
   export SECRET_KEY="test-secret-key"
   python app.py
   ```

2. **验证安全响应头**
   ```bash
   curl -I http://localhost:5000/login
   # 应返回 X-Content-Type-Options、X-Frame-Options、CSP 等
   ```

3. **验证未登录重定向**
   ```bash
   curl -s -o /dev/null -w "%{http_code} %{redirect_url}" http://localhost:5000/
   # 应返回 302 → /login
   ```

4. **验证 CSRF 防护**
   ```bash
   curl -X POST http://localhost:5000/login -d "username=admin&password=admin123"
   # 应返回"表单已过期"
   ```

5. **验证正常登录**
   - 访问登录页获取 CSRF Token
   - 使用正确账号密码 POST
   - 确认 302 重定向到首页
   - 确认首页显示"欢迎回来"

6. **验证密码不泄露**
   - 登录后查看页面源代码
   - 确认没有密码字段

7. **验证 404 页面**
   ```bash
   curl http://localhost:5000/nonexist
   # 应返回自定义 404 页面
   ```

8. **验证暴力破解防护**
   - 连续错误登录，确认第 6 次提示账户已锁定

---

## 七、总结与反思

### 安全开发原则

1. **永远不要存储明文密码** — 使用经过充分测试的哈希库（如 `werkzeug.security`、`bcrypt`、`argon2`）
2. **最小权限原则** — 不应在前端展示敏感字段（密码、密钥等）
3. **不要信任注释** — 代码注释中的敏感信息同样是安全风险
4. **使用安全的默认配置** — `debug=True` 仅用于开发环境，上线前必须关闭
5. **防御纵深** — 密码哈希防泄露，爆破防护防暴力破解，CSRF 防跨站请求，HTTPS 防中间人攻击
6. **永不硬编码密钥** — Secret Key 等敏感配置应从环境变量或密钥管理服务读取

### 本次修复覆盖的安全维度

| 维度 | 覆盖情况 |
|------|----------|
| 密码安全（存储、比对、强度） | ✅ 全部修复 |
| 认证安全（爆破、会话、CSRF） | ✅ 全部修复 |
| 配置安全（密钥、Debug、响应头） | ✅ 全部修复 |
| 代码质量（重复代码、硬编码） | ✅ 全部修复 |
| 用户体验（注册、错误页、响应式） | ✅ 全部修复 |

### 后续可继续优化的方向

- **HTTP 明文传输：** 生产环境必须使用 HTTPS + HSTS 防止中间人窃听
- **数据库持久化：** 当前使用内存字典，服务重启数据丢失。可替换为 SQLite 或 MySQL
- **验证码：** 登录页可添加 CAPTCHA 验证码，进一步增强防爆破能力
- **双因素认证：** 增加 TOTP 或短信验证码作为第二认证因素
- **账户管理：** 增加密码修改、密码重置（忘记密码）功能

---

## 八、参考资料

- [Flask 官方文档 — 安全考量](https://flask.palletsprojects.com/en/stable/security/)
- [Werkzeug 密码哈希文档](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)
- [Flask-Limiter 文档](https://flask-limiter.readthedocs.io/)
- [OWASP — 密码存储备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP — 爆破防护](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP — CSRF 防护](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 — 2021](https://owasp.org/www-project-top-ten/)

---

> **报告生成日期：** 2026-07-07
> **测试环境：** Kali Linux + Python Flask + Flask-Limiter + Werkzeug
> **GitHub 仓库：** https://github.com/Yu1478/flask-user-login
