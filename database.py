"""数据库模块 — SQLite 表结构与操作"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from config import DATABASE_PATH, AUDIT_LOG_RETENTION_DAYS


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """初始化数据库表结构"""
    conn = get_connection()
    cursor = conn.cursor()

    # 识别规则表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recognition_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            rule_type TEXT NOT NULL DEFAULT 'regex',
            pattern TEXT NOT NULL,
            description TEXT,
            sensitivity_level TEXT NOT NULL DEFAULT 'medium',
            category TEXT NOT NULL DEFAULT 'personal',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 脱敏策略表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS desensitization_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            rule_id INTEGER,
            method TEXT NOT NULL DEFAULT 'mask',
            mask_config TEXT DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rule_id) REFERENCES recognition_rules(id) ON DELETE SET NULL
        )
    """)

    # 白名单表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            whitelist_type TEXT NOT NULL,
            whitelist_value TEXT NOT NULL,
            description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 阻断策略表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS block_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            trigger_condition TEXT NOT NULL,
            block_level TEXT NOT NULL DEFAULT 'soft',
            block_message TEXT DEFAULT '您的请求中包含敏感信息，已被安全系统拦截。',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 审计日志表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT,
            client_ip TEXT,
            original_input TEXT,
            desensitized_input TEXT,
            model_output TEXT,
            triggered_rules TEXT,
            action_taken TEXT,
            block_level TEXT,
            processing_time_ms REAL,
            request_url TEXT
        )
    """)

    # 创建索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(request_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action_taken)")

    # 用户表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 插入默认识别规则
    _insert_default_rules(cursor)

    # 插入默认脱敏策略
    _insert_default_policies(cursor)

    # 插入默认阻断策略
    _insert_default_block_policies(cursor)

    # 插入默认管理员账号 admin / admin123
    _insert_default_admin(cursor)

    conn.commit()
    conn.close()


def _insert_default_rules(cursor):
    """插入默认敏感数据识别规则"""
    default_rules = [
        ("身份证号", "regex", r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)", "中国大陆居民身份证号码", "high", "personal"),
        ("手机号", "regex", r"(?<!\d)1[3-9]\d{9}(?!\d)", "中国大陆手机号码", "high", "personal"),
        ("银行卡号", "regex", r"(?<!\d)\d{16,19}(?!\d)", "银行卡号（16-19位数字）", "high", "personal"),
        ("邮箱地址", "regex", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "电子邮箱地址", "medium", "personal"),
        ("IP地址", "regex", r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", "IPv4地址", "medium", "network"),
        ("MAC地址", "regex", r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", "MAC地址", "medium", "network"),
        ("统一社会信用代码", "regex", r"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}", "企业统一社会信用代码", "medium", "business"),
        ("车牌号", "regex", r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]", "中国机动车号牌", "medium", "personal"),
        ("密码/密钥", "keyword", r"(?:password|passwd|secret|token|api_key|apikey|access_key|secret_key)\s*[:=]\s*\S+", "密码或API密钥等凭证信息", "high", "credential"),
        ("GPS坐标", "regex", r"(?<!\d)\d{1,3}\.\d{4,10}\s*[,，]\s*\d{1,3}\.\d{4,10}(?!\d)", "GPS地理坐标", "medium", "personal"),
    ]

    for name, rule_type, pattern, desc, level, category in default_rules:
        cursor.execute(
            "INSERT OR IGNORE INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category) VALUES (?, ?, ?, ?, ?, ?)",
            (name, rule_type, pattern, desc, level, category)
        )


def _insert_default_policies(cursor):
    """插入默认脱敏策略"""
    cursor.execute("SELECT id, name, sensitivity_level FROM recognition_rules WHERE enabled=1")
    rules = cursor.fetchall()

    for rule in rules:
        if rule["sensitivity_level"] == "high":
            method = "mask"
            mask_config = json.dumps({"keep_prefix": 3, "keep_suffix": 4, "mask_char": "*"})
        elif rule["sensitivity_level"] == "medium":
            method = "mask"
            mask_config = json.dumps({"keep_prefix": 2, "keep_suffix": 2, "mask_char": "*"})
        else:
            method = "mask"
            mask_config = json.dumps({"keep_prefix": 1, "keep_suffix": 1, "mask_char": "*"})

        cursor.execute(
            "INSERT OR IGNORE INTO desensitization_policies (name, rule_id, method, mask_config) VALUES (?, ?, ?, ?)",
            (f"{rule['name']}_脱敏策略", rule["id"], method, mask_config)
        )


def _insert_default_block_policies(cursor):
    """插入默认阻断策略"""
    defaults = [
        ("高危凭证泄露", "sensitivity_level == 'high' AND category == 'credential'", "hard", "检测到API密钥/密码泄露风险，请求已被阻断。"),
        ("批量敏感数据外传", "match_count > 10", "hard", "检测到大量敏感数据外传，请求已被阻断。"),
        ("中等敏感告警", "sensitivity_level == 'medium'", "soft", "您的请求包含敏感信息，已记录审计日志。"),
    ]
    for name, condition, level, msg in defaults:
        cursor.execute(
            "INSERT OR IGNORE INTO block_policies (name, trigger_condition, block_level, block_message) VALUES (?, ?, ?, ?)",
            (name, condition, level, msg)
        )


def _insert_default_admin(cursor):
    """插入默认管理员账号"""
    admin_pw = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", admin_pw, "admin")
    )


# ==================== 用户操作 ====================

def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_user(username, password):
    """验证用户名密码，成功返回用户信息，失败返回None"""
    user = get_user_by_username(username)
    if not user:
        return None
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash == user["password_hash"]:
        return user
    return None


def create_user(username, password, role="user"):
    conn = get_connection()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pw_hash, role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# ==================== 审计日志操作 ====================

def add_audit_log(user_id, client_ip, original_input, desensitized_input,
                  model_output, triggered_rules, action_taken, block_level,
                  processing_time_ms, request_url):
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_logs (user_id, client_ip, original_input, desensitized_input,
                                model_output, triggered_rules, action_taken, block_level,
                                processing_time_ms, request_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, client_ip, original_input, desensitized_input, model_output,
          json.dumps(triggered_rules, ensure_ascii=False), action_taken, block_level,
          processing_time_ms, request_url))
    conn.commit()
    conn.close()


def query_audit_logs(page=1, per_page=20, user_id=None, action=None, date_from=None, date_to=None):
    conn = get_connection()
    conditions = []
    params = []

    if user_id:
        conditions.append("user_id LIKE ?")
        params.append(f"%{user_id}%")
    if action:
        conditions.append("action_taken = ?")
        params.append(action)
    if date_from:
        conditions.append("request_time >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("request_time <= ?")
        params.append(date_to)

    where_clause = " AND ".join(conditions) if conditions else "1=1"
    offset = (page - 1) * per_page

    total = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {where_clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM audit_logs WHERE {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def get_audit_stats(user_id=None):
    """获取审计统计信息，可选按用户过滤"""
    conn = get_connection()
    user_filter = ""
    params = []
    if user_id:
        user_filter = " WHERE user_id = ?"
        params = [user_id]

    stats = {}
    stats["total"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs{user_filter}", params).fetchone()[0]
    stats["blocked"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='blocked' {'AND user_id = ?' if user_id else ''}", params).fetchone()[0]
    stats["desensitized"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='desensitized' {'AND user_id = ?' if user_id else ''}", params).fetchone()[0]
    stats["passed"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='passed' {'AND user_id = ?' if user_id else ''}", params).fetchone()[0]
    today_filter = f"date(request_time) = date('now') {'AND user_id = ?' if user_id else ''}"
    stats["today"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {today_filter}", params).fetchone()[0]
    conn.close()
    return stats


def get_daily_stats(days=30, user_id=None):
    """获取最近N天按日期聚合的统计，可选按用户过滤"""
    conn = get_connection()
    user_filter = "AND user_id = ?" if user_id else ""
    params = [f'-{days} days']
    if user_id:
        params.append(user_id)

    rows = conn.execute(f"""
        SELECT
            date(request_time) AS day,
            COUNT(*) AS total,
            SUM(CASE WHEN action_taken = 'passed' THEN 1 ELSE 0 END) AS passed,
            SUM(CASE WHEN action_taken = 'desensitized' THEN 1 ELSE 0 END) AS desensitized,
            SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END) AS blocked
        FROM audit_logs
        WHERE date(request_time) >= date('now', ?) {user_filter}
        GROUP BY date(request_time)
        ORDER BY day ASC
    """, params).fetchall()
    conn.close()

    # 填充没有数据的日期为0
    from datetime import date as dt
    today = dt.today()
    result = {}
    for i in range(days - 1, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        result[d] = {"total": 0, "passed": 0, "desensitized": 0, "blocked": 0}

    for row in rows:
        day = row["day"]
        if day in result:
            result[day] = {
                "total": row["total"],
                "passed": row["passed"] or 0,
                "desensitized": row["desensitized"] or 0,
                "blocked": row["blocked"] or 0,
            }

    return result


def cleanup_old_logs():
    """清理过期日志"""
    conn = get_connection()
    cutoff = (datetime.now() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)).strftime("%Y-%m-%d")
    conn.execute("DELETE FROM audit_logs WHERE date(request_time) < ?", (cutoff,))
    conn.commit()
    conn.close()


# ==================== 规则 CRUD ====================

def get_all_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM recognition_rules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_rule(name, rule_type, pattern, description, sensitivity_level, category):
    conn = get_connection()
    conn.execute(
        "INSERT INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category) VALUES (?, ?, ?, ?, ?, ?)",
        (name, rule_type, pattern, description, sensitivity_level, category)
    )
    conn.commit()
    conn.close()


def update_rule(rule_id, **kwargs):
    conn = get_connection()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [rule_id]
    conn.execute(f"UPDATE recognition_rules SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM recognition_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def get_enabled_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM recognition_rules WHERE enabled = 1 ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 策略 CRUD ====================

def get_all_policies():
    conn = get_connection()
    rows = conn.execute("""
        SELECT dp.*, rr.name as rule_name
        FROM desensitization_policies dp
        LEFT JOIN recognition_rules rr ON dp.rule_id = rr.id
        ORDER BY dp.id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_policy(policy_id, **kwargs):
    conn = get_connection()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [policy_id]
    conn.execute(f"UPDATE desensitization_policies SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_enabled_policies():
    conn = get_connection()
    rows = conn.execute("""
        SELECT dp.*, rr.name as rule_name, rr.pattern, rr.rule_type, rr.sensitivity_level, rr.category
        FROM desensitization_policies dp
        LEFT JOIN recognition_rules rr ON dp.rule_id = rr.id
        WHERE dp.enabled = 1 AND rr.enabled = 1
        ORDER BY dp.id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 白名单 CRUD ====================

def get_all_whitelist():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_whitelist(whitelist_type, whitelist_value, description):
    conn = get_connection()
    conn.execute(
        "INSERT INTO whitelist (whitelist_type, whitelist_value, description) VALUES (?, ?, ?)",
        (whitelist_type, whitelist_value, description)
    )
    conn.commit()
    conn.close()


def delete_whitelist(wl_id):
    conn = get_connection()
    conn.execute("DELETE FROM whitelist WHERE id = ?", (wl_id,))
    conn.commit()
    conn.close()


def get_enabled_whitelist():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM whitelist WHERE enabled = 1").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 阻断策略 CRUD ====================

def get_all_block_policies():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM block_policies ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_block_policy(policy_id, **kwargs):
    conn = get_connection()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [policy_id]
    conn.execute(f"UPDATE block_policies SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_enabled_block_policies():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM block_policies WHERE enabled = 1").fetchall()
    conn.close()
    return [dict(r) for r in rows]