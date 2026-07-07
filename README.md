# 🧑‍💻 Flask 用户管理系统

一个基于 Python Flask 的用户信息管理平台，提供登录、注册、登出、用户信息展示等功能。

## 📋 功能特性

- ✅ 用户登录 / 登出
- ✅ 用户注册（含密码强度校验、重复密码校验）
- ✅ Session 会话管理
- ✅ 登录验证装饰器保护路由
- ✅ CSRF 跨站请求伪造防护
- ✅ 密码哈希存储（使用 Werkzeug）
- ✅ 用户信息展示（用户名、邮箱、手机、角色、余额）
- ✅ 卡片式 UI 设计，蓝色渐变导航栏
- ✅ 响应式布局，支持移动端访问
- ✅ 自定义 404/500 错误页面
- ✅ 操作日志记录

## 🛠️ 技术栈

| 技术 | 说明 |
|------|------|
| **Python 3** | 编程语言 |
| **Flask** | Web 框架 |
| **Werkzeug** | 密码哈希工具 |
| **HTML + CSS** | 前端界面 |

## 📁 项目结构

```
flask-user-login/
├── app.py                  # Flask 主应用（路由、认证、配置）
├── SECURITY_REPORT.md      # 项目评估与改进报告
├── README.md               # 项目说明文档
├── templates/
│   ├── base.html           # 基础模板（导航栏 + 布局容器）
│   ├── login.html          # 登录页面
│   ├── register.html       # 注册页面
│   ├── index.html          # 首页（用户信息展示）
│   └── error.html          # 404/500 错误页面
└── static/css/
    └── style.css           # 全局样式（导航栏、卡片、表单、按钮）
```

## 🚀 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/Yu1478/flask-user-login.git
cd flask-user-login
```

### 2. 安装依赖

```bash
pip install flask
```

Flask 内置了 `werkzeug`，无需额外安装。

### 3. 运行服务

```bash
python app.py
```

服务默认启动在 **http://0.0.0.0:5000**

### 4. 访问

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
- 登录失败显示错误提示
- 提供"立即注册"快捷链接

### 注册页 `/register`
- 支持 CSRF 保护的注册表单
- 用户名唯一性校验
- 密码长度不少于 6 位
- 两次密码输入一致性校验
- 注册成功后跳转到登录页

### 错误页 `/error`
- 404：页面不存在提示 + 返回首页按钮
- 500：服务器内部错误提示 + 返回首页按钮

## ⚙️ 环境变量配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SECRET_KEY` | Flask session 加密密钥 | `dev-key-2025` |
| `FLASK_DEBUG` | 调试模式（`1` 开启，`0` 关闭） | `0` |

生产环境建议设置：

```bash
export SECRET_KEY="your-strong-secret-key-here"
export FLASK_DEBUG=0
```

## 🔒 安全特性

本项目已修复全部 7 项安全漏洞和 9 项架构质量问题（详见 [SECURITY_REPORT.md](./SECURITY_REPORT.md)）：

### 安全防护
- ✅ 密码哈希存储（Werkzeug）
- ✅ CSRF Token 防护
- ✅ Session 安全配置（HttpOnly、SameSite）
- ✅ 登录验证装饰器
- ✅ 敏感数据过滤（密码不进入模板）

### 代码质量
- ✅ POST/REDIRECT/GET 模式
- ✅ 使用 `url_for` 而非硬编码路径
- ✅ 提取公共函数消除重复代码
- ✅ 操作日志记录（登录/登出/注册）

## 📝 开发说明

- **数据存储**：当前使用内存字典（`USERS`），服务重启后数据重置。如需持久化，可替换为 SQLite 或 MySQL。
- **页面样式**：纯 CSS 实现，支持移动端自适应。
- **扩展建议**：可在此基础上添加用户资料修改、头像上传、角色权限管理等进阶功能。

## 📜 许可证

本项目仅供学习和参考使用。
