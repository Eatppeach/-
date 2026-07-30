"""大模型数据防护能力平台 — Flask 主应用"""

import json
import time
import os
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, session

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "llm-data-protection-secret-key-2026")

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
)
from proxy_gateway import gateway


# ==================== 权限装饰器 ====================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "需要管理员权限"}), 403
            return render_template("index.html", stats={}, error="需要管理员权限"), 403
        return f(*args, **kwargs)
    return decorated


def _get_user_filter():
    """普通用户返回自己的 user_id 用于过滤，管理员返回 None"""
    if session.get("role") == "admin":
        return None
    return session.get("username")


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
        return jsonify({"ok": True, "role": user["role"], "username": user["username"]})
    return jsonify({"ok": False, "error": "用户名或密码错误"}), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ==================== Web 管理界面 ====================

@app.route("/")
@login_required
def index():
    user_filter = _get_user_filter()
    stats = get_audit_stats(user_id=user_filter)
    return render_template("index.html", stats=stats)


@app.route("/rules")
@login_required
@admin_required
def rules_page():
    rules = get_all_rules()
    return render_template("rules.html", rules=rules)


@app.route("/policies")
@login_required
@admin_required
def policies_page():
    policies = get_all_policies()
    return render_template("policies.html", policies=policies)


@app.route("/whitelist")
@login_required
@admin_required
def whitelist_page():
    whitelist = get_all_whitelist()
    return render_template("whitelist.html", whitelist=whitelist)


@app.route("/block")
@login_required
@admin_required
def block_page():
    block_policies = get_all_block_policies()
    return render_template("block.html", block_policies=block_policies)


@app.route("/audit")
@login_required
def audit_page():
    page = request.args.get("page", 1, type=int)
    user_id = request.args.get("user_id", "")
    action = request.args.get("action", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")

    # 普通用户只能看自己的日志
    if session.get("role") != "admin":
        user_id = session.get("username")

    logs, total = query_audit_logs(
        page=page, per_page=20,
        user_id=user_id or None,
        action=action or None,
        date_from=date_from or None,
        date_to=date_to or None,
    )
    total_pages = max(1, (total + 19) // 20)
    return render_template("audit.html", logs=logs, page=page, total_pages=total_pages,
                           total=total, user_id=user_id, action=action,
                           date_from=date_from, date_to=date_to)


@app.route("/demo")
@login_required
def demo_page():
    return render_template("demo.html")


# ==================== API — 规则管理 ====================

@app.route("/api/rules/reload", methods=["POST"])
@admin_required
def api_reload_rules():
    gateway.refresh()
    return jsonify({"status": "ok", "message": "规则已刷新"})


@app.route("/api/rules", methods=["GET"])
@admin_required
def api_get_rules():
    return jsonify(get_all_rules())


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
    )
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
    return jsonify(get_all_policies())


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
    return jsonify(get_all_whitelist())


@app.route("/api/whitelist", methods=["POST"])
@admin_required
def api_add_whitelist():
    data = request.json
    add_whitelist(
        whitelist_type=data["whitelist_type"],
        whitelist_value=data["whitelist_value"],
        description=data.get("description", ""),
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
    return jsonify(get_all_block_policies())


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

    # 普通用户只能看自己的日志
    if session.get("role") != "admin":
        user_id = session.get("username")

    logs, total = query_audit_logs(page=page, user_id=user_id, action=action,
                                   date_from=date_from, date_to=date_to)
    return jsonify({"logs": logs, "total": total, "page": page})


@app.route("/api/audit/stats", methods=["GET"])
@login_required
def api_get_audit_stats():
    user_filter = _get_user_filter()
    return jsonify(get_audit_stats(user_id=user_filter))


@app.route("/api/stats/daily", methods=["GET"])
@login_required
def api_daily_stats():
    days = request.args.get("days", 30, type=int)
    user_filter = _get_user_filter()
    return jsonify(get_daily_stats(days, user_id=user_filter))


@app.route("/api/audit/cleanup", methods=["POST"])
@admin_required
def api_cleanup_logs():
    cleanup_old_logs()
    return jsonify({"status": "ok"})


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


@app.route("/api/gateway/chat", methods=["POST"])
def api_chat_proxy():
    """大模型对话代理接口 — 完整安全处理 + 流式转发"""
    data = request.json
    user_input = data.get("message") or data.get("text", "")

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


# ==================== 启动 ====================

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  大模型数据防护能力平台")
    print(f"  管理后台: http://localhost:5000")
    print(f"  代理网关: http://localhost:5000/api/gateway/chat")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)