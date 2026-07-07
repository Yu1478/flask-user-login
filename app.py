from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# 明文密码用户数据库 —— 切勿用于生产环境
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


@app.route("/")
def index():
    """首页：已登录则展示用户信息，未登录则提示登录。"""
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面：GET 返回表单，POST 校验身份。"""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
        else:
            error = "用户名或密码错误，请重试。"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """登出：清除 session 后重定向到首页。"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
