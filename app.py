import os
import re
import secrets
from datetime import timedelta
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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ─── 强制要求生产密钥 ───────────────────────────────────────────
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "严重安全错误：必须设置环境变量 SECRET_KEY。\n"
        "   export SECRET_KEY=\"your-strong-secret-key-here\""
    )

# ─── Session 安全配置 ──────────────────────────────────────────
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# 生产环境开启 Secure（仅 HTTPS）
if os.environ.get("ENABLE_HTTPS", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True
# Session 超时：2 小时无操作需重新登录
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# ─── 登录速率限制（暴力破解防护）───────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)


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

# ─── 登录失败计数器（内存中的简单账户锁定）───────────────────────
LOGIN_FAILURES: dict[str, int] = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


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


def validate_password_strength(password):
    """校验密码强度：≥8 位，包含大写、小写、数字、特殊字符。"""
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


def is_account_locked(username):
    """检查账户是否已被锁定。"""
    if username in LOGIN_FAILURES:
        attempts, lock_time = LOGIN_FAILURES[username]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            elapsed = (__import__("time").time() - lock_time) / 60
            if elapsed < LOGIN_LOCKOUT_MINUTES:
                remaining = int(LOGIN_LOCKOUT_MINUTES - elapsed)
                return True, remaining
            else:
                # 锁定时间已过，清零
                del LOGIN_FAILURES[username]
    return False, 0


def record_login_failure(username):
    """记录登录失败次数。"""
    now = __import__("time").time()
    if username in LOGIN_FAILURES:
        attempts, _ = LOGIN_FAILURES[username]
        LOGIN_FAILURES[username] = (attempts + 1, now)
    else:
        LOGIN_FAILURES[username] = (1, now)


# ─── 登录装饰器 ────────────────────────────────────────────────


def login_required(f):
    """登录验证装饰器：未登录用户重定向到登录页。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ─── 安全响应头 ────────────────────────────────────────────────


@app.after_request
def add_security_headers(response):
    """为所有响应添加安全头部。"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # 已废弃但兼容旧浏览器
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ─── 路由 ──────────────────────────────────────────────────────


@app.route("/")
@login_required
def index():
    """首页：展示当前登录用户的完整信息（不含密码）。"""
    username = session["username"]
    user_info = get_safe_user(username)
    if user_info is None:
        session.pop("username", None)
        return redirect(url_for("login"))
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
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

        # 账户锁定检查
        locked, remaining = is_account_locked(username)
        if locked:
            error = f"账户已锁定，请 {remaining} 分钟后再试。"
            app.logger.warning(f"账户 {username} 已被锁定")
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # 登录成功：Session Fixation 防护
            session.clear()
            session.permanent = True
            session["username"] = username
            # 清除该用户的失败记录
            LOGIN_FAILURES.pop(username, None)
            app.logger.info(f"用户 {username} 登录成功")
            return redirect(url_for("index"))
        else:
            record_login_failure(username)
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
        elif password != confirm_password:
            error = "两次密码输入不一致。"
        else:
            # 密码强度校验
            pwd_error = validate_password_strength(password)
            if pwd_error:
                error = pwd_error
            else:
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


@app.errorhandler(429)
def ratelimit_error(e):
    """速率限制触发时的处理。"""
    return render_template("error.html", code=429, message="请求过于频繁，请稍后再试。"), 429


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ─── 启动 ──────────────────────────────────────────────────────

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
