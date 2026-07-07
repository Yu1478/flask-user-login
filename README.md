# 🧑‍💻 Flask 用户管理系统

一个基于 Python Flask 的简易用户信息管理平台，提供登录、登出、用户信息展示等功能。

## 📋 功能特性

- ✅ 用户登录 / 登出
- ✅ Session 会话管理
- ✅ 登录验证装饰器保护路由
- ✅ 用户信息展示（用户名、邮箱、手机、角色、余额）
- ✅ 卡片式 UI 设计，蓝色渐变导航栏

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
├── SECURITY_REPORT.md      # 安全漏洞报告与修复记录
├── README.md               # 项目说明文档
├── templates/
│   ├── base.html           # 基础模板（导航栏 + 布局容器）
│   ├── login.html          # 登录页面
│   └── index.html          # 首页（用户信息展示）
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

本项目已修复以下安全漏洞（详见 [SECURITY_REPORT.md](./SECURITY_REPORT.md)）：

| # | 漏洞 | 修复方式 |
|---|------|----------|
| 1 | 密码明文存储 | 改用 `generate_password_hash` 哈希存储 |
| 2 | 密码明文比对 | 改用 `check_password_hash` 哈希比对 |
| 3 | 首页展示密码 | 传递模板时过滤 `password` 字段 |
| 4 | Secret Key 硬编码 | 从环境变量 `SECRET_KEY` 读取 |
| 5 | 无登录装饰器 | 新增 `@login_required` 统一验证 |
| 6 | Debug 模式开启 | 由 `FLASK_DEBUG` 环境变量控制 |
| 7 | HTML 注释泄露密码 | 删除明文密码注释 |

## 📄 页面说明

### 首页 `/`

- **已登录**：显示"欢迎回来，用户名！"以及用户的完整信息（不含密码）
- **未登录**：显示"请先登录"提示和跳转按钮
- 已登录状态提供"退出登录"按钮

### 登录页 `/login`

- 卡片式登录表单
- 输入用户名和密码进行登录
- 登录失败显示错误提示

### 登出 `/logout`

- 清除当前会话
- 自动跳转回首页

## 📝 开发说明

- 用户数据目前存储在内存字典中（`USERS`），服务重启后数据会重置
- 如需持久化存储，可替换为 SQLite、MySQL 等数据库
- 页面样式使用纯 CSS，位于 `static/css/style.css`

## 📜 许可证

本项目仅供学习和参考使用。
