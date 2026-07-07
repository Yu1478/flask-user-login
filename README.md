# 🧑‍💻 Flask 用户管理系统

一个基于 Python Flask 的用户信息管理平台，提供登录、注册、登出、用户信息展示等功能。

**网络安全实训项目**：从漏洞挖掘到安全修复，最终交付一份具备生产级别安全防护的 Web 应用。

## 📋 功能特性

- ✅ 用户登录 / 登出
- ✅ 用户注册（含密码强度校验、重复密码校验）
- ✅ Session 会话管理（HttpOnly + SameSite + 超时机制）
- ✅ 登录验证装饰器保护路由
- ✅ CSRF 跨站请求伪造防护
- ✅ 密码哈希存储（Werkzeug）
- ✅ 暴力破解防护（速率限制 + 账户锁定）
- ✅ Session Fixation 防护
- ✅ 安全响应头（CSP、X-Frame-Options 等）
- ✅ 用户信息展示（用户名、邮箱、手机、角色、余额）
- ✅ 操作日志记录
- ✅ 卡片式 UI 设计，蓝色渐变导航栏
- ✅ 响应式布局，支持移动端访问
- ✅ 自定义 404/429/500 错误页面

## 🛠️ 技术栈

| 技术 | 说明 |
|------|------|
| **Python 3** | 编程语言 |
| **Flask** | Web 框架 |
| **Flask-Limiter** | 速率限制（暴力破解防护） |
| **Werkzeug** | 密码哈希工具 |
| **HTML + CSS** | 前端界面 |
| **Gunicorn** | 生产级 WSGI 服务器 |

## 📁 项目结构

```
flask-user-login/
├── app.py                  # Flask 主应用（路由、认证、配置）
├── requirements.txt        # Python 依赖清单
├── .gitignore              # Git 忽略规则
├── SECURITY_REPORT.md      # 项目评估与改进报告
├── README.md               # 项目说明文档（本文件）
├── templates/
│   ├── base.html           # 基础模板（导航栏 + 布局容器）
│   ├── login.html          # 登录页面
│   ├── register.html       # 注册页面
│   ├── index.html          # 首页（用户信息展示）
│   └── error.html          # 404/429/500 错误页面
└── static/css/
    └── style.css           # 全局样式
```

## 🚀 快速开始（开发环境）

### 1. 克隆项目

```bash
git clone https://github.com/Yu1478/flask-user-login.git
cd flask-user-login
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 设置环境变量

```bash
export SECRET_KEY="dev-key-2025"
```

### 4. 运行服务

```bash
python app.py
```

服务默认启动在 **http://0.0.0.0:5000**

### 5. 访问

打开浏览器访问：**http://localhost:5000**

## 🔑 默认账号

| 用户名 | 密码 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|------|
| `admin` | `admin123` | admin | admin@example.com | 13800138000 | 99999 |
| `alice` | `alice2025` | user | alice@example.com | 13900139001 | 100 |

> ⚠️ **安全提醒**：以上为开发环境默认账号，部署前请修改密码！

## ✨ 页面一览

### 首页 `/`
- 已登录：展示用户完整信息（用户名、邮箱、手机、角色、余额）
- 未登录：自动跳转到登录页
- 提供"退出登录"按钮

### 登录页 `/login`
- 支持 CSRF 保护的登录表单
- 速率限制保护（单 IP 每分钟 10 次）
- 连续 5 次失败后锁定账户 15 分钟
- 登录失败显示错误提示
- 提供"立即注册"快捷链接

### 注册页 `/register`
- 支持 CSRF 保护的注册表单
- 用户名唯一性校验
- 密码强度要求：≥ 8 位 + 大小写字母 + 数字 + 特殊字符
- 两次密码输入一致性校验
- 注册成功后提示前往登录

### 错误页 `/error`
- 404：页面不存在提示 + 返回首页按钮
- 429：请求过于频繁提示 + 返回首页按钮
- 500：服务器内部错误提示 + 返回首页按钮

## ⚙️ 环境变量配置

| 变量名 | 说明 | 必填 | 默认值 |
|--------|------|------|--------|
| `SECRET_KEY` | Flask session 加密密钥 | ✅ **是** | 无（不设置则启动报错） |
| `FLASK_DEBUG` | 调试模式（`1` 开启） | ❌ | `0`（关闭） |
| `ENABLE_HTTPS` | 启用 HTTPS 模式（`1` 开启） | ❌ | `0` |

## 🔒 安全特性（共 22 项改进）

### 密码安全
- ✅ 密码哈希存储（Werkzeug `generate_password_hash`）
- ✅ 密码哈希比对（`check_password_hash`）
- ✅ 密码强度校验（8 位 + 大写 + 小写 + 数字 + 特殊字符）
- ✅ 敏感信息过滤（密码不进入模板渲染）

### 访问控制
- ✅ 登录验证装饰器（`@login_required`）
- ✅ CSRF Token 防护
- ✅ 登录速率限制（flask-limiter，每分钟 10 次）
- ✅ 账户锁定机制（5 次失败锁定 15 分钟）

### Session 安全
- ✅ Session Fixation 防护（登录时 `session.clear()`）
- ✅ Session 超时机制（2 小时无操作自动过期）
- ✅ HttpOnly 标记（防止 JS 窃取 cookie）
- ✅ SameSite=Lax 策略（CSRF 防护）
- ✅ Secret Key 强制从环境变量读取

### HTTP 安全
- ✅ Content-Security-Policy 响应头
- ✅ X-Content-Type-Options: nosniff
- ✅ X-Frame-Options: DENY
- ✅ Referrer-Policy 响应头
- ✅ Debug 模式默认关闭

### 监控与运维
- ✅ 操作日志记录（登录成功/失败/登出/注册）
- ✅ 自定义 404/429/500 错误页面

## 🏭 生产环境部署

### 使用 Gunicorn

```bash
# 1. 设置安全密钥（生产环境必须使用高强度随机字符串）
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 2. 确保 debug 关闭
export FLASK_DEBUG=0

# 3. 安装 gunicorn
pip install gunicorn

# 4. 启动（4 个 worker 进程）
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### 推荐架构：Nginx 反向代理 + HTTPS

```nginx
# /etc/nginx/sites-available/flask-app
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

启用 HTTPS 后设置环境变量：
```bash
export ENABLE_HTTPS=1
```

## 📝 开发说明

- **数据存储**：当前使用内存字典（`USERS`），服务重启后数据重置。如需持久化，可替换为 SQLite 或 MySQL。
- **依赖管理**：使用 `pip install -r requirements.txt` 安装依赖。
- **代码规范**：项目遵循 PEP 8 编码规范，关键函数均有文档字符串。

## 🧪 快速验证安全配置

```bash
# 检查安全响应头
curl -I http://localhost:5000/login | grep -E '(X-Content|X-Frame|CSP|Referrer)'

# 检查 CSRF 防护（不带 token 应返回错误）
curl -X POST http://localhost:5000/login -d "username=admin&password=admin123"

# 检查未登录重定向
curl -s -o /dev/null -w "%{http_code} %{redirect_url}" http://localhost:5000/
```

## 📚 相关文档

- [SECURITY_REPORT.md](./SECURITY_REPORT.md) — 完整的漏洞挖掘、修复过程与安全增强报告

## 📜 许可证

本项目仅供网络安全实训教学使用。
