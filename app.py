import os
import secrets
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-2025")

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ─── 用户数据库 ────────────────────────────────────────────────
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


# ─── 辅助函数 ──────────────────────────────────────────────────


def get_safe_user(username):
    """获取不包含密码字段的用户信息。"""
    user = USERS.get(username)
    if user:
        return {k: v for k, v in user.items() if k != "password"}
    return None


def generate_csrf_token():
    """生成 CSRF token 并存入 session。"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token):
    """校验 CSRF token。"""
    stored = session.pop("_csrf_token", None)
    return stored and token == stored


# ─── 登录装饰器 ────────────────────────────────────────────────


def login_required(f):
    """登录验证装饰器：未登录用户重定向到登录页。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ─── 路由 ──────────────────────────────────────────────────────


@app.route("/")
@login_required
def index():
    """首页：展示当前登录用户的完整信息（不含密码）。"""
    username = session["username"]
    user_info = get_safe_user(username)
    if user_info is None:
        # session 中的用户已被删除，清除 session 并要求重新登录
        session.pop("username", None)
        return redirect(url_for("login"))
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面：GET 返回表单，POST 校验身份。"""
    error = None
    if request.method == "POST":
        # CSRF 校验
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            error = "表单已过期，请重新提交。"
            app.logger.warning("CSRF token 校验失败")
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            app.logger.info(f"用户 {username} 登录成功")
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误，请重试。"
            app.logger.warning(f"用户 {username} 登录失败")

    return render_template("login.html", error=error, csrf_token=generate_csrf_token())


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面：新用户自行注册。"""
    error = None
    success = None
    if request.method == "POST":
        # CSRF 校验
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            error = "表单已过期，请重新提交。"
            return render_template("register.html", error=error, csrf_token=generate_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 字段校验
        if not username or not password or not email:
            error = "用户名、密码和邮箱为必填项。"
        elif username in USERS:
            error = "用户名已存在，请换一个。"
        elif len(password) < 6:
            error = "密码长度不能少于 6 位。"
        elif password != confirm_password:
            error = "两次密码输入不一致。"
        else:
            # 注册成功
            USERS[username] = {
                "username": username,
                "password": generate_password_hash(password),
                "role": "user",
                "email": email,
                "phone": phone,
                "balance": 0,
            }
            app.logger.info(f"新用户 {username} 注册成功")
            success = "注册成功！请前往登录。"

    return render_template(
        "register.html",
        error=error,
        success=success,
        csrf_token=generate_csrf_token(),
    )


@app.route("/logout")
def logout():
    """登出：清除 session 后重定向到首页。"""
    username = session.get("username")
    if username:
        app.logger.info(f"用户 {username} 已登出")
    session.clear()
    return redirect(url_for("index"))


# ─── 错误处理 ──────────────────────────────────────────────────


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="页面不存在"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ─── 启动 ──────────────────────────────────────────────────────

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
