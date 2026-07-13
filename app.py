from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, uuid, time

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# 允许的图片扩展名
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
# 允许的 MIME 类型
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

# 登录失败锁定
LOGIN_FAILURES = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def allowed_file(filename):
    """检查文件扩展名是否在白名单内"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_actual_image(filepath):
    """通过文件头魔数验证文件是否为真实图片"""
    try:
        with open(filepath, "rb") as f:
            header = f.read(12)
        # PNG: 89 50 4E 47 0D 0A 1A 0A
        if header[:8] == b"\x89PNG\r\n\x1a\n":
            return True
        # JPEG: FF D8 FF
        if header[:3] == b"\xff\xd8\xff":
            return True
        # GIF: 47 49 46 38 39 61 或 47 49 46 38 37 61
        if header[:6] in (b"GIF89a", b"GIF87a"):
            return True
        # WebP: 52 49 46 46 x x x x 57 45 42 50
        if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return True
        return False
    except Exception:
        return False


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
    # 确保上传目录存在
    os.makedirs("static/uploads", exist_ok=True)


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


def get_user_by_id(user_id):
    """根据用户 ID 查询用户信息（不含 password 字段）"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user.pop("password", None)
        return user
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
    """登录页面 - 含暴力破解防护"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 检查是否锁定
        if username in LOGIN_FAILURES:
            attempts, lock_time = LOGIN_FAILURES[username]
            if attempts >= MAX_ATTEMPTS:
                elapsed = (time.time() - lock_time) / 60
                if elapsed < LOCKOUT_MINUTES:
                    remaining = int(LOCKOUT_MINUTES - elapsed)
                    return render_template("login.html", error=f"账户已临时锁定，请 {remaining} 分钟后再试")
                else:
                    del LOGIN_FAILURES[username]

        user_full = get_user_full(username)
        if user_full and check_password_hash(user_full["password"], password):
            session["username"] = username
            LOGIN_FAILURES.pop(username, None)
            user_info = {k: v for k, v in user_full.items() if k != "password"}
            return render_template("index.html", user=user_info)
        else:
            # 记录失败
            now = time.time()
            if username in LOGIN_FAILURES:
                cnt, _ = LOGIN_FAILURES[username]
                LOGIN_FAILURES[username] = (cnt + 1, now)
            else:
                LOGIN_FAILURES[username] = (1, now)
            return render_template("login.html", error="用户名或密码错误，请重试")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面 - 含密码强度校验"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 密码强度校验
        if len(password) < 6:
            return render_template("register.html", error="密码长度不能少于 6 位")

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
        except Exception:
            conn.close()
            # 统一错误信息，不区分"用户名已存在"还是其他错误
            return render_template("register.html", error="注册失败，请检查信息后重试")

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
                "SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?",
                (f"%{keyword}%", f"%{keyword}%")
            )
            rows = c.fetchall()
            results = [dict(row) for row in rows]
        except Exception:
            # 静默处理查询异常
            pass
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """头像上传 - 需要登录，带文件类型和内容校验"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件")

        # 检查扩展名
        if not allowed_file(file.filename):
            return render_template("upload.html", error="只允许上传图片文件（png, jpg, jpeg, gif, webp）")

        # 防止路径穿越：使用 secure_filename 清洗文件名
        safe_filename = secure_filename(file.filename)
        # 检查清洗后文件名是否还有扩展名（防止无扩展名文件导致 crash）
        if "." not in safe_filename:
            return render_template("upload.html", error="无效的文件名，请重新选择文件")

        # 用 UUID 重命名，防止文件名冲突和双扩展名绕过
        ext = safe_filename.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join("static/uploads", unique_name)

        # 先保存到临时路径，魔数校验通过后再保留
        try:
            file.save(file_path)
        except Exception:
            return render_template("upload.html", error="文件保存失败，请重试")

        # 通过文件头魔数验证真实内容
        try:
            if not is_actual_image(file_path):
                os.remove(file_path)
                return render_template("upload.html", error="文件内容不是有效的图片，请上传真实图片文件")
        except Exception:
            # 校验异常时清理已保存的文件
            if os.path.exists(file_path):
                os.remove(file_path)
            return render_template("upload.html", error="文件校验失败，请重试")

        file_url = url_for("static", filename=f"uploads/{unique_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=unique_name)

    return render_template("upload.html")


@app.route("/profile")
def profile():
    """个人中心 - 只能查看自己的资料"""
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_info = get_user_by_username(username)
    if not user_info:
        session.pop("username", None)
        return redirect("/login")

    return render_template("profile.html", user=user_info)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 - 只能给当前登录用户充值，金额必须大于 0"""
    if "username" not in session:
        return redirect("/login")

    amount = request.form.get("amount")
    if not amount:
        return redirect("/")

    try:
        amount = float(amount)
    except ValueError:
        return redirect("/profile")

    if amount <= 0:
        return redirect("/profile?error=充值金额必须大于0")

    username = session["username"]
    user_info = get_user_by_username(username)
    if not user_info:
        return redirect("/login")

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_info["id"]))
    conn.commit()
    conn.close()

@app.route("/page")
def dynamic_page():
    """动态页面加载 - 修复文件包含漏洞"""
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_error="请提供页面名称")

    # 防止路径遍历：规范化路径并检查是否在 pages/ 范围内
    requested_path = os.path.join("pages", name)
    real_path = os.path.realpath(requested_path)
    pages_dir = os.path.realpath("pages")

    if not real_path.startswith(pages_dir):
        return render_template("index.html", page_error="页面不存在")

    page_content = None

    # 先尝试直接读
    if os.path.exists(real_path) and os.path.isfile(real_path):
        with open(real_path, "r", encoding="utf-8") as f:
            page_content = f.read()
    else:
        # 尝试加 .html 后缀
        html_path = real_path + ".html"
        if os.path.exists(html_path) and os.path.isfile(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            return render_template("index.html", page_error="页面不存在")

    return render_template("index.html", page_content=page_content)


@app.route("/logout")
def logout():
    """登出 - 清除 session 后重定向到首页"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
