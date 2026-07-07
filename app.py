import os
from functools import wraps
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-2025")

# 用户数据库 —— 密码已使用哈希存储
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def login_required(f):
    """登录验证装饰器：未登录用户重定向到登录页。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    """首页：展示当前登录用户的完整信息（不含密码）。"""
    username = session["username"]
    user_info = USERS.get(username)
    # 过滤掉密码字段，不传入模板
    safe_info = {k: v for k, v in user_info.items() if k != "password"}
    return render_template("index.html", user=safe_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面：GET 返回表单，POST 校验身份。"""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            user_info = USERS.get(username)
            safe_info = {k: v for k, v in user_info.items() if k != "password"}
            return render_template("index.html", user=safe_info)
        else:
            error = "用户名或密码错误，请重试。"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """登出：清除 session 后重定向到首页。"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
