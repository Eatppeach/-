"""大模型数据防护能力平台 — Flask 主应用"""

import json
import time
import os
import secrets
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, session, g

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "llm-data-protection-secret-key-2026")


# ==================== 速率限制器 ====================

class RateLimiter:
    """基于滑动窗口的 IP 速率限制器，支持按租户动态配置"""

    def __init__(self, default_max=60, window_seconds=60):
        self.default_max = default_max
        self.window = window_seconds
        self._store = defaultdict(list)

    def is_limited(self, key, max_requests=None):
        """检查是否超限，max_requests=None 时使用默认值，=0 表示不限制"""
        if max_requests is not None and max_requests <= 0:
            return False  # 不限流
        limit = max_requests if max_requests is not None else self.default_max

        now = time.time()
        cutoff = now - self.window
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        if len(self._store[key]) >= limit:
            return True
        self._store[key].append(now)
        return False


# 为不同路由创建不同的限流器
gateway_limiter = RateLimiter(default_max=60, window_seconds=60)
login_limiter = RateLimiter(default_max=30, window_seconds=60)  # 登录接口更严格

# 必须先初始化数据库，再导入依赖数据库的模块
from database import init_db
init_db()

from database import (
    get_all_rules, add_rule, update_rule, delete_rule,
    get_all_policies, update_policy,
    get_all_whitelist, add_whitelist, delete_whitelist,
    get_all_block_policies, update_block_policy,
    query_audit_logs, get_audit_stats, get_daily_stats, cleanup_old_logs,
    verify_user, create_user, get_user_by_username,
    get_all_tenants, get_tenant_by_id, create_tenant, update_tenant, delete_tenant,
    get_tenant_users, create_tenant_user, update_tenant_user, delete_tenant_user,
    get_tenant_self_info, update_tenant_self, get_tenant_stats,
    get_global_overview, get_tenant_rate_limit,
)
from proxy_gateway import gateway


# ==================== 请求前处理 ====================

@app.before_request
def load_request_context():
    """每个请求前自动注入用户上下文到 g 对象，CSRF Token 管理，速率限制"""
    # --- 用户上下文 ---
    g.user_id = session.get("user_id")
    g.username = session.get("username")
    g.role = session.get("role")
    g.tenant_id = session.get("tenant_id")

    # --- CSRF Token 生成 ---
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    g.csrf_token = session["csrf_token"]

    # --- 速率限制 ---
    client_ip = request.remote_addr or "127.0.0.1"

    # 获取当前租户的速率限制配置（如果有）
    tenant_rpm = None
    if g.tenant_id:
        try:
            cfg = get_tenant_rate_limit(g.tenant_id)
            if not cfg["enabled"]:
                tenant_rpm = 0  # 0 表示不限流
            else:
                tenant_rpm = cfg["rpm"]
        except Exception:
            pass  # 数据库查询失败时使用默认值

    # /api/gateway/* 速率限制
    if request.path.startswith("/api/gateway/"):
        if gateway_limiter.is_limited(client_ip, max_requests=tenant_rpm):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({
                    "error": "请求过于频繁，请稍后再试",
                    "retry_after": 60
                }), 429
            return "请求过于频繁，请稍后再试", 429

    # /login 和 /register 速率限制（不受租户配置影响，始终使用固定限制）
    if request.path in ("/login", "/register") and request.method == "POST":
        if login_limiter.is_limited(client_ip):
            return jsonify({
                "ok": False,
                "error": "登录/注册请求过于频繁，请 60 秒后再试",
                "retry_after": 60
            }), 429

    # --- CSRF Token 校验（仅对状态变更请求） ---
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # 跳过不需要 CSRF 保护的路由
        skip_csrf_paths = ("/login", "/register", "/api/gateway/", "/api/csrf-token")
        if any(request.path.startswith(p) for p in skip_csrf_paths):
            return

        token = request.headers.get("X-CSRF-Token")
        if not token or token != session.get("csrf_token"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({
                    "error": "CSRF Token 验证失败，请刷新页面后重试",
                    "code": "CSRF_INVALID"
                }), 403
            return "CSRF Token 验证失败", 403


# ==================== 模板上下文注入 ====================

@app.context_processor
def inject_csrf_token():
    """将所有模板注入 CSRF Token"""
    return {"csrf_token": session.get("csrf_token", "")}


# ==================== 权限装饰器 ====================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user_id:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user_id:
            return redirect(url_for("login_page"))
        if g.role not in ("admin", "super_admin"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "需要管理员权限"}), 403
            return render_template("index.html", stats={}, error="需要管理员权限"), 403
        return f(*args, **kwargs)
    return decorated


def super_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user_id:
            return redirect(url_for("login_page"))
        if g.role != "super_admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "需要超级管理员权限"}), 403
            return render_template("index.html", stats={}, error="需要超级管理员权限"), 403
        return f(*args, **kwargs)
    return decorated


def _get_user_filter():
    """普通用户返回自己的 username 用于过滤，管理员返回 None（查看全部）"""
    if g.role in ("admin", "super_admin"):
        return None
    return g.username


def _get_tenant_filter():
    """租户管理员返回自己的 tenant_id 用于数据隔离，超级管理员返回 None（查看全部）"""
    if g.role == "super_admin":
        return None
    return g.tenant_id


# ==================== 登录/登出 ====================

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def do_login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = verify_user(username, password)
    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["tenant_id"] = user.get("tenant_id")
        return jsonify({"ok": True, "role": user["role"], "username": user["username"]})
    return jsonify({"ok": False, "error": "用户名或密码错误"}), 401


@app.route("/register", methods=["POST"])
def do_register():
    """用户自助注册（仅限普通用户）"""
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or len(username) < 2:
        return jsonify({"ok": False, "error": "用户名至少2个字符"}), 400
    if not password or len(password) < 6:
        return jsonify({"ok": False, "error": "密码至少6位"}), 400

    # 检查用户名是否已存在
    existing = get_user_by_username(username)
    if existing:
        return jsonify({"ok": False, "error": "用户名已存在"}), 409

    # 注册到默认租户
    ok = create_user(username, password, role="user", tenant_id=1)
    if not ok:
        return jsonify({"ok": False, "error": "注册失败，请重试"}), 500

    # 注册成功，自动登录
    user = get_user_by_username(username)
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["tenant_id"] = user.get("tenant_id")
    return jsonify({"ok": True, "role": user["role"], "username": user["username"]})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ==================== Web 管理界面 ====================

@app.route("/")
@login_required
def index():
    tenant_id = _get_tenant_filter()
    stats = get_tenant_stats(tenant_id=tenant_id)
    return render_template("index.html", stats=stats)


@app.route("/rules")
@login_required
@admin_required
def rules_page():
    rules = get_all_rules(tenant_id=_get_tenant_filter())
    return render_template("rules.html", rules=rules)


@app.route("/policies")
@login_required
@admin_required
def policies_page():
    policies = get_all_policies(tenant_id=_get_tenant_filter())
    return render_template("policies.html", policies=policies)


@app.route("/security-rules")
@login_required
@admin_required
def security_rules_page():
    rules = get_all_rules(tenant_id=_get_tenant_filter())
    policies = get_all_policies(tenant_id=_get_tenant_filter())
    return render_template("security_rules.html", rules=rules, policies=policies)


@app.route("/whitelist")
@login_required
@admin_required
def whitelist_page():
    whitelist = get_all_whitelist(tenant_id=_get_tenant_filter())
    return render_template("whitelist.html", whitelist=whitelist)


@app.route("/block")
@login_required
@admin_required
def block_page():
    block_policies = get_all_block_policies(tenant_id=_get_tenant_filter())
    return render_template("block.html", block_policies=block_policies)


@app.route("/audit")
@login_required
def audit_page():
    page = request.args.get("page", 1, type=int)
    user_id = request.args.get("user_id", "")
    action = request.args.get("action", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    tenant_id = _get_tenant_filter()

    # 普通用户只能看自己的日志
    if g.role not in ("admin", "super_admin"):
        user_id = g.username

    logs, total = query_audit_logs(
        page=page, per_page=20,
        user_id=user_id or None,
        action=action or None,
        date_from=date_from or None,
        date_to=date_to or None,
        tenant_id=tenant_id,
    )
    total_pages = max(1, (total + 19) // 20)
    return render_template("audit.html", logs=logs, page=page, total_pages=total_pages,
                           total=total, user_id=user_id, action=action,
                           date_from=date_from, date_to=date_to)


@app.route("/demo")
@login_required
def demo_page():
    return render_template("demo.html")


# ==================== 租户管理（超级管理员） ====================

@app.route("/admin/tenants")
@super_admin_required
def tenants_page():
    tenants = get_all_tenants()
    return render_template("admin_tenants.html", tenants=tenants)


@app.route("/admin/global")
@super_admin_required
def global_view_page():
    """超级管理员跨租户全局视图"""
    return render_template("admin_global.html")


@app.route("/api/tenants", methods=["GET"])
@super_admin_required
def api_get_tenants():
    return jsonify(get_all_tenants())


@app.route("/api/tenants", methods=["POST"])
@super_admin_required
def api_create_tenant():
    data = request.json
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "租户名称不能为空"}), 400
    tenant_id = create_tenant(
        name=name,
        description=data.get("description", ""),
        contact=data.get("contact", ""),
        max_users=data.get("max_users", 50),
        rate_limit_enabled=data.get("rate_limit_enabled", True),
        rate_limit_rpm=data.get("rate_limit_rpm", 60),
    )
    if tenant_id is None:
        return jsonify({"error": "租户名称已存在"}), 409

    # 同时创建初始管理员账号
    admin_user = data.get("admin_username", "").strip()
    admin_pass = data.get("admin_password", "")
    if admin_user and admin_pass:
        if len(admin_pass) < 6:
            return jsonify({"error": "管理员密码至少6位"}), 400
        ok = create_tenant_user(tenant_id, admin_user, admin_pass, role="admin")
        if not ok:
            return jsonify({"error": "管理员用户名已存在"}), 409

    return jsonify({"status": "ok", "tenant_id": tenant_id})


@app.route("/api/tenants/<int:tenant_id>", methods=["PUT"])
@super_admin_required
def api_update_tenant(tenant_id):
    data = request.json
    ok = update_tenant(tenant_id, **data)
    if not ok:
        return jsonify({"error": "更新失败，无有效字段"}), 400
    return jsonify({"status": "ok"})


@app.route("/api/tenants/<int:tenant_id>", methods=["DELETE"])
@super_admin_required
def api_delete_tenant(tenant_id):
    delete_tenant(tenant_id)
    return jsonify({"status": "ok"})


@app.route("/api/tenants/<int:tenant_id>/users", methods=["GET"])
@super_admin_required
def api_get_tenant_users(tenant_id):
    return jsonify(get_tenant_users(tenant_id))


@app.route("/api/tenants/<int:tenant_id>/users", methods=["POST"])
@super_admin_required
def api_create_tenant_user(tenant_id):
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    ok = create_tenant_user(tenant_id, username, password, role)
    if not ok:
        return jsonify({"error": "用户名已存在"}), 409
    return jsonify({"status": "ok"})


# ==================== 租户自助管理（租户管理员） ====================

@app.route("/admin/users")
@admin_required
def tenant_users_page():
    """租户管理员管理本租户用户"""
    if g.role == "super_admin":
        return redirect(url_for("tenants_page"))
    tenant_info = get_tenant_self_info(g.tenant_id)
    users = get_tenant_users(g.tenant_id)
    return render_template("admin_tenant_users.html", tenant=tenant_info, users=users)


@app.route("/api/tenant/profile", methods=["GET"])
@admin_required
def api_get_tenant_profile():
    """租户管理员获取本租户信息"""
    if g.role == "super_admin":
        return jsonify({"error": "超级管理员请使用租户管理功能"}), 400
    info = get_tenant_self_info(g.tenant_id)
    return jsonify(info)


@app.route("/api/tenant/profile", methods=["PUT"])
@admin_required
def api_update_tenant_profile():
    """租户管理员更新本租户信息"""
    if g.role == "super_admin":
        return jsonify({"error": "超级管理员请使用租户管理功能"}), 400
    data = request.json
    ok = update_tenant_self(g.tenant_id, **data)
    if not ok:
        return jsonify({"error": "无有效字段"}), 400
    return jsonify({"status": "ok"})


@app.route("/api/tenant/users", methods=["GET"])
@admin_required
def api_get_my_users():
    """租户管理员获取本租户用户列表"""
    if g.role == "super_admin":
        return jsonify(get_tenant_users(request.args.get("tenant_id", type=int)))
    return jsonify(get_tenant_users(g.tenant_id))


@app.route("/api/tenant/users", methods=["POST"])
@admin_required
def api_create_my_user():
    """租户管理员在本租户下创建用户"""
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")

    if g.role == "super_admin":
        tenant_id = data.get("tenant_id", g.tenant_id)
    else:
        tenant_id = g.tenant_id
        # 租户管理员不能创建 admin 角色用户
        if role == "admin":
            return jsonify({"error": "租户管理员不能创建管理员用户"}), 403

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    ok = create_tenant_user(tenant_id, username, password, role)
    if not ok:
        return jsonify({"error": "用户名已存在"}), 409
    return jsonify({"status": "ok"})


@app.route("/api/tenant/users/<int:user_id>", methods=["PUT"])
@admin_required
def api_update_my_user(user_id):
    """租户管理员更新用户信息"""
    data = request.json
    kwargs = {}
    if "username" in data:
        kwargs["username"] = data["username"].strip()
    if "role" in data:
        if g.role != "super_admin" and data["role"] == "admin":
            return jsonify({"error": "租户管理员不能设置管理员角色"}), 403
        kwargs["role"] = data["role"]
    if "password" in data:
        import hashlib
        kwargs["password_hash"] = hashlib.sha256(data["password"].encode()).hexdigest()
    ok = update_tenant_user(user_id, **kwargs)
    if not ok:
        return jsonify({"error": "无有效更新字段"}), 400
    return jsonify({"status": "ok"})


@app.route("/api/tenant/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_delete_my_user(user_id):
    """租户管理员删除用户"""
    delete_tenant_user(user_id)
    return jsonify({"status": "ok"})


# ==================== API — 规则管理 ====================

@app.route("/api/rules/reload", methods=["POST"])
@admin_required
def api_reload_rules():
    gateway.refresh()
    return jsonify({"status": "ok", "message": "规则已刷新"})


@app.route("/api/rules", methods=["GET"])
@admin_required
def api_get_rules():
    return jsonify(get_all_rules(tenant_id=_get_tenant_filter()))


@app.route("/api/rules", methods=["POST"])
@admin_required
def api_add_rule():
    data = request.json
    add_rule(
        name=data["name"],
        rule_type=data.get("rule_type", "regex"),
        pattern=data["pattern"],
        description=data.get("description", ""),
        sensitivity_level=data.get("sensitivity_level", "medium"),
        category=data.get("category", "personal"),
        tenant_id=_get_tenant_filter(),
    )
    # 自动创建对应的脱敏策略
    rules = get_all_rules(tenant_id=_get_tenant_filter())
    new_rule = next((r for r in rules if r["name"] == data["name"]), None)
    if new_rule:
        import json as _json
        from database import get_connection, _tenant_where
        conn = get_connection()
        mask_config = _json.dumps({"keep_prefix": 0, "keep_suffix": 0, "mask_char": "x"}) if new_rule["category"] == "business" else _json.dumps({"keep_prefix": 3, "keep_suffix": 4, "mask_char": "*"})
        conn.execute(
            "INSERT OR IGNORE INTO desensitization_policies (name, rule_id, method, mask_config, tenant_id) VALUES (?, ?, ?, ?, ?)",
            (f"{new_rule['name']}_脱敏策略", new_rule["id"], "mask", mask_config, _get_tenant_filter())
        )
        conn.commit()
        conn.close()
    # 自动刷新规则到内存
    gateway.refresh()
    return jsonify({"status": "ok"})


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
@admin_required
def api_update_rule(rule_id):
    data = request.json
    update_rule(rule_id, **data)
    return jsonify({"status": "ok"})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def api_delete_rule(rule_id):
    delete_rule(rule_id)
    return jsonify({"status": "ok"})


# ==================== API — 策略管理 ====================

@app.route("/api/policies", methods=["GET"])
@admin_required
def api_get_policies():
    return jsonify(get_all_policies(tenant_id=_get_tenant_filter()))


@app.route("/api/policies/<int:policy_id>", methods=["PUT"])
@admin_required
def api_update_policy(policy_id):
    data = request.json
    update_policy(policy_id, **data)
    return jsonify({"status": "ok"})


# ==================== API — 白名单管理 ====================

@app.route("/api/whitelist", methods=["GET"])
@admin_required
def api_get_whitelist():
    return jsonify(get_all_whitelist(tenant_id=_get_tenant_filter()))


@app.route("/api/whitelist", methods=["POST"])
@admin_required
def api_add_whitelist():
    data = request.json
    add_whitelist(
        whitelist_type=data["whitelist_type"],
        whitelist_value=data["whitelist_value"],
        description=data.get("description", ""),
        tenant_id=_get_tenant_filter(),
    )
    return jsonify({"status": "ok"})


@app.route("/api/whitelist/<int:wl_id>", methods=["DELETE"])
@admin_required
def api_delete_whitelist(wl_id):
    delete_whitelist(wl_id)
    return jsonify({"status": "ok"})


# ==================== API — 阻断策略 ====================

@app.route("/api/block_policies", methods=["GET"])
@admin_required
def api_get_block_policies():
    return jsonify(get_all_block_policies(tenant_id=_get_tenant_filter()))


@app.route("/api/block_policies/<int:policy_id>", methods=["PUT"])
@admin_required
def api_update_block_policy(policy_id):
    data = request.json
    update_block_policy(policy_id, **data)
    return jsonify({"status": "ok"})


# ==================== API — 审计日志 ====================

@app.route("/api/audit", methods=["GET"])
@login_required
def api_get_audit():
    page = request.args.get("page", 1, type=int)
    user_id = request.args.get("user_id")
    action = request.args.get("action")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    tenant_id = _get_tenant_filter()

    # 普通用户只能看自己的日志
    if session.get("role") not in ("admin", "super_admin"):
        user_id = session.get("username")

    logs, total = query_audit_logs(page=page, user_id=user_id, action=action,
                                   date_from=date_from, date_to=date_to, tenant_id=tenant_id)
    return jsonify({"logs": logs, "total": total, "page": page})


@app.route("/api/audit/stats", methods=["GET"])
@login_required
def api_get_audit_stats():
    user_filter = _get_user_filter()
    return jsonify(get_audit_stats(user_id=user_filter, tenant_id=_get_tenant_filter()))


@app.route("/api/stats/daily", methods=["GET"])
@login_required
def api_daily_stats():
    days = request.args.get("days", 30, type=int)
    user_filter = _get_user_filter()
    return jsonify(get_daily_stats(days, user_id=user_filter, tenant_id=_get_tenant_filter()))


@app.route("/api/audit/cleanup", methods=["POST"])
@admin_required
def api_cleanup_logs():
    cleanup_old_logs()
    return jsonify({"status": "ok"})


# ==================== API — 全局视图（超级管理员） ====================

@app.route("/api/global/overview", methods=["GET"])
@super_admin_required
def api_global_overview():
    """跨租户全局视图数据"""
    return jsonify(get_global_overview())


# ==================== 代理网关核心API ====================

@app.route("/api/gateway/scan", methods=["POST"])
def api_scan():
    """扫描文本中的敏感信息（不执行脱敏）"""
    data = request.json
    text = data.get("text", "")
    user_id = data.get("user_id", request.headers.get("X-User-ID"))
    client_ip = request.remote_addr

    result = gateway.process_request(text, client_ip=client_ip, user_id=user_id)
    return jsonify({
        "action": result["action"],
        "scan_result": result["scan_result"],
        "processing_time_ms": result["processing_time_ms"],
    })


@app.route("/api/gateway/protect", methods=["POST"])
def api_protect():
    """对输入文本执行完整安全检测与脱敏处理"""
    data = request.json
    text = data.get("text", "")
    user_id = data.get("user_id", request.headers.get("X-User-ID"))
    client_ip = request.remote_addr

    result = gateway.process_request(text, client_ip=client_ip, user_id=user_id)
    return jsonify({
        "action": result["action"],
        "block_level": result["block_level"],
        "block_message": result["block_message"],
        "processed_text": result["processed_input"],
        "scan_result": result["scan_result"],
        "processing_time_ms": result["processing_time_ms"],
    })


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload_file():
    """文件上传解析接口 — 提取 Word/PDF 文本内容"""
    if "file" not in request.files:
        return jsonify({"error": "未选择文件"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "文件名为空"}), 400

    filename = file.filename.lower()
    allowed_extensions = (".docx", ".pdf", ".txt", ".md")
    if not filename.endswith(allowed_extensions):
        return jsonify({"error": f"不支持的文件类型，仅支持: {', '.join(allowed_extensions)}"}), 400

    try:
        file_bytes = file.read()
        text = ""

        if filename.endswith(".docx"):
            from docx import Document
            from io import BytesIO
            doc = Document(BytesIO(file_bytes))
            text = "\n".join([p.text for p in doc.paragraphs if p.text.strip()])

        elif filename.endswith(".pdf"):
            import fitz
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            text = "\n".join([page.get_text() for page in doc])
            doc.close()

        elif filename.endswith(".txt") or filename.endswith(".md"):
            text = file_bytes.decode("utf-8", errors="replace")

        if not text.strip():
            return jsonify({"error": "未能从文件中提取到文本内容"}), 400

        # 限制最大字符数，防止超出 LLM 上下文窗口
        max_chars = 30000
        if len(text) > max_chars:
            text = text[:max_chars] + f"\n\n[文档过长，已截断至前 {max_chars} 字符]"

        return jsonify({
            "filename": file.filename,
            "text": text,
            "char_count": len(text),
        })

    except Exception as e:
        return jsonify({"error": f"文件解析失败: {str(e)}"}), 500


@app.route("/api/gateway/chat", methods=["POST"])
def api_chat_proxy():
    """大模型对话代理接口 — 完整安全处理 + 流式转发"""
    data = request.json
    user_input = data.get("message") or data.get("text", "")

    # 文档内容拼接到用户消息前面
    document_text = data.get("document_text", "")
    if document_text:
        user_input = f"以下是文档内容：\n{document_text}\n\n用户问题：{user_input}"

    messages = data.get("messages", [])
    if messages and not user_input:
        user_input = messages[-1].get("content", "") if messages else ""

    # 对话历史（不含最后一条用户消息）
    history = data.get("history", [])
    if not history and len(messages) > 1:
        history = messages[:-1]

    user_id = data.get("user_id", request.headers.get("X-User-ID"))
    client_ip = request.remote_addr
    upstream_url = data.get("upstream_url", "")
    api_key = data.get("api_key", request.headers.get("X-API-Key", ""))
    model = data.get("model", "gpt-3.5-turbo")
    stream = data.get("stream", False)

    # 安全检测与脱敏
    result = gateway.process_request(
        user_input, client_ip=client_ip, user_id=user_id,
        request_url=upstream_url
    )

    if result["action"] == "blocked" and result["block_level"] == "hard":
        return jsonify({
            "error": True,
            "block_level": "hard",
            "message": result["block_message"],
            "scan_result": result["scan_result"],
        }), 403

    processed_input = result["processed_input"]

    if not upstream_url:
        return jsonify({
            "action": result["action"],
            "block_level": result["block_level"],
            "block_message": result["block_message"],
            "processed_text": processed_input,
            "scan_result": result["scan_result"],
            "processing_time_ms": result["processing_time_ms"],
        })

    if stream:
        def generate():
            for chunk in gateway.stream_llm_response(
                processed_input, upstream_url, api_key, model, history
            ):
                yield chunk

        return Response(
            generate(),
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )
    else:
        llm_response = gateway.forward_to_llm(
            processed_input, upstream_url, api_key, model, history=history
        )
        return jsonify({
            "action": result["action"],
            "processed_input": processed_input,
            "llm_response": llm_response,
            "scan_result": result["scan_result"],
            "processing_time_ms": result["processing_time_ms"],
        })


@app.route("/chat")
@login_required
def chat_page():
    resp = app.make_response(render_template("chat.html"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/architecture")
def architecture_page():
    return render_template("architecture.html")


# ==================== CSRF Token 端点 ====================

@app.route("/api/csrf-token")
def api_csrf_token():
    """获取当前会话的 CSRF Token（用于 SPA 页面动态获取）"""
    return jsonify({"csrf_token": session.get("csrf_token", "")})


# ==================== 启动 ====================

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  大模型数据防护能力平台")
    print(f"  管理后台: http://localhost:8080")
    print(f"  代理网关: http://localhost:8080/api/gateway/chat")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8080, debug=True)