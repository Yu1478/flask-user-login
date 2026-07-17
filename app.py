from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, uuid, time, secrets
import urllib.request, urllib.error, urllib.parse
import socket, subprocess, re, json

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


def generate_csrf_token():
    """生成 CSRF token 并存入 session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token):
    """校验 CSRF token"""
    stored = session.pop("_csrf_token", None)
    return stored and token == stored


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

        # CSRF 校验
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return render_template("login.html", error="表单已过期，请重新提交",
                                   csrf_token=generate_csrf_token())

        # 检查是否锁定
        if username in LOGIN_FAILURES:
            attempts, lock_time = LOGIN_FAILURES[username]
            if attempts >= MAX_ATTEMPTS:
                elapsed = (time.time() - lock_time) / 60
                if elapsed < LOCKOUT_MINUTES:
                    remaining = int(LOCKOUT_MINUTES - elapsed)
                    return render_template("login.html", error=f"账户已临时锁定，请 {remaining} 分钟后再试",
                                           csrf_token=generate_csrf_token())
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
            return render_template("login.html", error="用户名或密码错误，请重试",
                                   csrf_token=generate_csrf_token())

    return render_template("login.html", csrf_token=generate_csrf_token())


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面 - 含密码强度校验"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # CSRF 校验
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return render_template("register.html", error="表单已过期，请重新提交",
                                   csrf_token=generate_csrf_token())

        # 密码强度校验
        if len(password) < 6:
            return render_template("register.html", error="密码长度不能少于 6 位",
                                   csrf_token=generate_csrf_token())

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
            return render_template("login.html", success="注册成功，请登录",
                                   csrf_token=generate_csrf_token())
        except Exception:
            conn.close()
            # 统一错误信息，不区分"用户名已存在"还是其他错误
            return render_template("register.html", error="注册失败，请检查信息后重试",
                                   csrf_token=generate_csrf_token())

    return render_template("register.html", csrf_token=generate_csrf_token())


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

        # CSRF 校验
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return render_template("upload.html", error="表单已过期，请重新提交",
                                   csrf_token=generate_csrf_token())

        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件",
                                   csrf_token=generate_csrf_token())

        # 检查扩展名
        if not allowed_file(file.filename):
            return render_template("upload.html", error="只允许上传图片文件（png, jpg, jpeg, gif, webp）",
                                   csrf_token=generate_csrf_token())

        # 防止路径穿越：使用 secure_filename 清洗文件名
        safe_filename = secure_filename(file.filename)
        # 检查清洗后文件名是否还有扩展名（防止无扩展名文件导致 crash）
        if "." not in safe_filename:
            return render_template("upload.html", error="无效的文件名，请重新选择文件",
                                   csrf_token=generate_csrf_token())

        # 用 UUID 重命名，防止文件名冲突和双扩展名绕过
        ext = safe_filename.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join("static/uploads", unique_name)

        # 先保存到临时路径，魔数校验通过后再保留
        try:
            file.save(file_path)
        except Exception:
            return render_template("upload.html", error="文件保存失败，请重试",
                                   csrf_token=generate_csrf_token())

        # 通过文件头魔数验证真实内容
        try:
            if not is_actual_image(file_path):
                os.remove(file_path)
                return render_template("upload.html", error="文件内容不是有效的图片，请上传真实图片文件",
                                       csrf_token=generate_csrf_token())
        except Exception:
            # 校验异常时清理已保存的文件
            if os.path.exists(file_path):
                os.remove(file_path)
            return render_template("upload.html", error="文件校验失败，请重试",
                                   csrf_token=generate_csrf_token())

        file_url = url_for("static", filename=f"uploads/{unique_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=unique_name,
                               csrf_token=generate_csrf_token())

    return render_template("upload.html", csrf_token=generate_csrf_token())


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

    return render_template("profile.html", user=user_info, csrf_token=generate_csrf_token())


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 - 只能给当前登录用户充值，金额必须大于 0"""
    if "username" not in session:
        return redirect("/login")

    # CSRF 校验
    csrf_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return redirect("/profile?error=表单已过期，请重新提交")

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
    return redirect("/profile")

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


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 - 需原密码校验，仅限当前登录用户"""
    if "username" not in session:
        return redirect("/login")

    # CSRF 校验
    csrf_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return render_template("profile.html", error="表单已过期，请重新提交",
                               user=get_user_by_username(session["username"]),
                               csrf_token=generate_csrf_token())

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not new_password or not old_password:
        return render_template("profile.html", error="请填写所有密码字段",
                               user=get_user_by_username(session["username"]),
                               csrf_token=generate_csrf_token())

    # 新密码长度校验
    if len(new_password) < 6:
        return render_template("profile.html", error="新密码长度不能少于 6 位",
                               user=get_user_by_username(session["username"]),
                               csrf_token=generate_csrf_token())

    # 确认密码校验
    if new_password != confirm_password:
        return render_template("profile.html", error="两次密码输入不一致",
                               user=get_user_by_username(session["username"]),
                               csrf_token=generate_csrf_token())

    # 从 session 获取用户名，不从表单获取
    username = session["username"]

    # 验证原密码
    user_full = get_user_full(username)
    if not user_full or not check_password_hash(user_full["password"], old_password):
        return render_template("profile.html", error="原密码错误",
                               user=get_user_by_username(username),
                               csrf_token=generate_csrf_token())

    hashed_pw = generate_password_hash(new_password)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, username))
    conn.commit()
    conn.close()

    return redirect("/profile")


def is_internal_ip(hostname):
    """检查主机名是否解析到内网/保留地址"""
    try:
        # 检查是否为 localhost 字符串
        if hostname.lower() in ("localhost", "localhost.localdomain"):
            return True

        # 解析域名获取 IP 地址
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip = addr[4][0]

            # 检查 IPv6 回环地址
            if ip == "::1":
                return True

            # 检查 IPv4 mapped IPv6 地址（::ffff:x.x.x.x）
            if ip.startswith("::ffff:"):
                ipv4_part = ip[7:]  # 去掉 "::ffff:" 前缀
            else:
                ipv4_part = ip

            # 按 IPv4 地址格式检查
            parts = ipv4_part.split(".")
            if len(parts) == 4:
                try:
                    first = int(parts[0])
                    second = int(parts[1])
                except ValueError:
                    continue  # 非纯数字的 IP 段，跳过

                # 127.x.x.x — 回环地址
                if first == 127:
                    return True
                # 10.x.x.x — A 类私有地址
                if first == 10:
                    return True
                # 172.16-31.x.x — B 类私有地址
                if first == 172 and 16 <= second <= 31:
                    return True
                # 192.168.x.x — C 类私有地址
                if first == 192 and second == 168:
                    return True
                # 0.0.0.0 — 未指定地址
                if first == 0:
                    return True
                # 169.254.x.x — 链路本地地址
                if first == 169 and second == 254:
                    return True

        return False
    except Exception:
        # 解析失败时拒绝（安全优先）
        return True


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取 - 修复 SSRF 漏洞"""
    if "username" not in session:
        return redirect("/login")

    target_url = request.form.get("url", "")
    if not target_url:
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="请输入 URL")

    # ① 检查是否包含控制字符（CRLF 注入防护）
    # 检查原始字符和 URL 编码后的字符（%0d, %0a, %0D, %0A 等）
    for ch in target_url:
        if ord(ch) < 32 or ord(ch) == 127:
            return render_template("index.html",
                                   user=get_user_by_username(session["username"]),
                                   fetch_error="URL 包含非法字符")
    # 检查 URL 编码的 CRLF（%0d, %0a）
    if re.search(r'%0[dDaA]', target_url, re.IGNORECASE):
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="URL 包含非法字符")

    # ② 检查协议（仅允许 http 和 https）
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="不支持的协议，仅允许 http 和 https")

    if not parsed.hostname:
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="URL 格式无效")

    # ② 检查目标是否为内网地址（SSRF 防护）
    if is_internal_ip(parsed.hostname):
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="不允许访问内网地址")

    try:
        req = urllib.request.Request(target_url)

        # ③ 禁用重定向（防止 302 跳转到内网地址的 SSRF 绕过）
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)

        with opener.open(req, timeout=10) as response:
            status_code = response.getcode()
            content = response.read().decode("utf-8", errors="ignore")
            if len(content) > 5000:
                content = content[:5000] + "\n\n...（内容已截断，仅显示前 5000 字符）"

        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_status=status_code,
                               fetch_content=content,
                               fetch_url=target_url)

    except urllib.error.HTTPError as e:
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error=f"HTTP 错误: {e.code}")
    except urllib.error.URLError:
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="URL 请求失败，无法访问目标地址")
    except Exception:
        return render_template("index.html",
                               user=get_user_by_username(session["username"]),
                               fetch_error="请求失败，请检查 URL 后重试")


def validate_ip_or_hostname(target):
    """验证输入是否为合法的 IP 地址或域名，防止命令注入"""
    # 检查长度（防止 DoS 和 ping 参数缓冲区溢出）
    if len(target) > 150:
        return False

    # 拒绝包含不可见/控制字符的输入
    for ch in target:
        if ord(ch) < 32 or ord(ch) == 127:  # 控制字符
            return False
        if ch in (';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '!', '#'):
            return False

    # 拒绝非 ASCII 字符（防止 IDN 同形异义字绕过）
    if not all(ord(c) < 128 for c in target):
        return False

    # 允许 IPv4 地址
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True
        return False

    # 允许合法域名（仅字母、数字、点、短横线）
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    if re.match(hostname_pattern, target):
        return True

    return False


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断 - 修复命令注入漏洞"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            return render_template("ping.html", error="请输入 IP 地址或域名")

        # 输入校验：必须是合法 IP 或域名
        if not validate_ip_or_hostname(ip):
            return render_template("ping.html", error="无效的 IP 地址或域名格式")

        # 使用参数列表方式执行，禁用 shell=True，杜绝命令注入
        command = ["ping", "-c", "3", ip]
        try:
            output = subprocess.check_output(command, timeout=30,
                                              stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError:
            result = "Ping 命令执行失败，目标地址无响应"
        except subprocess.TimeoutExpired:
            result = "Ping 命令执行超时（30 秒）"
        except FileNotFoundError:
            result = "Ping 命令未找到，请检查系统配置"
        except Exception:
            result = "Ping 执行过程中发生未知错误"

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """XML 数据导入 - 存在 XXE 漏洞"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")
        if not xml_data:
            return render_template("xml_import.html", error="请输入 XML 数据")

        import xml.etree.ElementTree as ET

        try:
            # 检测 XML 中的 <!ENTITY 定义，提取 SYSTEM 后面的文件路径
            # 手动读取文件内容替换实体引用（存在 XXE 漏洞）
            entity_pattern = re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"')
            entity_matches = entity_pattern.findall(xml_data)

            for filepath in entity_matches:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        file_content = f.read()
                    # 将 &xxe; 等实体引用替换为文件内容
                    xml_data = re.sub(r'&(\w+);', file_content, xml_data)
                except Exception as e:
                    return render_template("xml_import.html",
                                           error=f"读取文件失败: {str(e)}")

            # 解析替换后的 XML，提取 user 节点的 name 和 email
            root = ET.fromstring(xml_data)

            results = []
            for user_elem in root.findall("user"):
                name = user_elem.findtext("name", "")
                email = user_elem.findtext("email", "")
                results.append({"name": name, "email": email})

            json_result = json.dumps(results, ensure_ascii=False, indent=2)
            return render_template("xml_import.html", result=json_result)

        except ET.ParseError as e:
            return render_template("xml_import.html",
                                   error=f"XML 解析失败: {e}")
        except Exception as e:
            return render_template("xml_import.html",
                                   error=f"处理失败: {str(e)}")

    return render_template("xml_import.html")


@app.route("/logout")
def logout():
    """登出 - 清除 session 后重定向到首页"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
