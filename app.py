from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 插入默认种子用户（密码已哈希），已存在则忽略
    c.execute(
        "INSERT OR IGNORE INTO users (username, password, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)",
        ("admin", generate_password_hash("admin123"), "admin", "admin@example.com", "13800138000", 99999)
    )
    c.execute(
        "INSERT OR IGNORE INTO users (username, password, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)",
        ("alice", generate_password_hash("alice2025"), "user", "alice@example.com", "13900139001", 100)
    )
    conn.commit()
    conn.close()


def get_user_by_username(username):
    """根据用户名查询用户信息（返回 dict，不含 password 字段）"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user.pop("password", None)
        return user
    return None


def get_user_full(username):
    """根据用户名查询用户完整信息（含 password 字段，仅用于登录校验）"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


@app.route("/")
def index():
    """首页 - 展示当前登录用户信息或提示登录"""
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_by_username(username)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_full = get_user_full(username)
        if user_full and check_password_hash(user_full["password"], password):
            session["username"] = username
            # 传递不含密码的用户信息
            user_info = {k: v for k, v in user_full.items() if k != "password"}
            return render_template("index.html", user=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误，请重试")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面 - 使用参数化查询修复 SQL 注入"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 密码哈希后再存入数据库
        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            # 使用参数化查询（? 占位符），杜绝 SQL 注入
            c.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, phone)
            )
            conn.commit()
            conn.close()
            return render_template("login.html", success="注册成功，请登录")
        except Exception as e:
            conn.close()
            # 不暴露原始数据库错误给用户
            return render_template("register.html", error="注册失败，该用户名可能已存在")

    return render_template("register.html")


@app.route("/search")
def search():
    """搜索用户 - 使用参数化查询修复 SQL 注入"""
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_by_username(username)

    results = []
    if keyword:
        # 使用参数化查询，keyword 作为参数传入 LIKE 模式
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        try:
            c.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (f"%{keyword}%", f"%{keyword}%")
            )
            rows = c.fetchall()
            results = [dict(row) for row in rows]
        except Exception:
            # 静默处理查询异常
            pass
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


@app.route("/logout")
def logout():
    """登出 - 清除 session 后重定向到首页"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    # 生产环境不应使用 debug 模式
    app.run(debug=False, host="0.0.0.0", port=5000)
