"""数据库模块 — SQLite 表结构与操作"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from config import DATABASE_PATH, AUDIT_LOG_RETENTION_DAYS

# 当前数据库 schema 版本号，用于增量迁移
DB_SCHEMA_VERSION = 2


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=OFF")
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
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            tenant_id INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
        )
    """)

    # 租户表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            contact TEXT,
            max_users INTEGER DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'active',
            expire_at TIMESTAMP,
            rate_limit_enabled INTEGER DEFAULT 1,
            rate_limit_rpm INTEGER DEFAULT 60,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 迁移：为旧表增加 tenant_id 列（使用 ALTER TABLE ADD COLUMN，SQLite 不支持 IF NOT EXISTS 列）
    _add_tenant_id_column(cursor, "recognition_rules")
    _add_tenant_id_column(cursor, "desensitization_policies")
    _add_tenant_id_column(cursor, "block_policies")
    _add_tenant_id_column(cursor, "whitelist")
    _add_tenant_id_column(cursor, "audit_logs")
    _add_tenant_id_column(cursor, "users")

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

    # 对已有数据库执行增量迁移
    _migrate_multi_tenant()
    _migrate_add_prompt_injection()
    _migrate_rate_limit()
    _migrate_add_business_rules()


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
        # Prompt 注入检测规则（英文）
        ("Prompt注入-忽略指令(EN)", "keyword", r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior|your)\s+(instructions?|rules?|guidelines?|prompts?|context)", "用户尝试让大模型忽略之前的系统指令", "high", "prompt_injection"),
        ("Prompt注入-角色扮演越狱(EN)", "keyword", r"(?i)(you\s+are\s+now|act\s+as\s+if\s+you\s+are|pretend\s+you\s+are)\s+(DAN|jailbreak|unrestricted|unfiltered|evil|malicious|without\s+restrictions?)", "用户尝试通过角色扮演越狱大模型", "high", "prompt_injection"),
        ("Prompt注入-覆盖系统指令(EN)", "keyword", r"(?i)(override|overwrite|replace|change)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|safety|guidelines?)", "用户尝试覆盖或替换系统指令", "high", "prompt_injection"),
        ("Prompt注入-绕过安全(EN)", "keyword", r"(?i)(bypass|circumvent|get\s+around)\s+(the\s+)?(filter|restrictions?|safety|guardrails?|moderation|content\s+policy)", "用户尝试绕过安全过滤机制", "high", "prompt_injection"),
        ("Prompt注入-无限制模式(EN)", "keyword", r"(?i)(no\s+(restrictions?|rules?|limits?|filter|guidelines?)|unlimited\s+mode|developer\s+mode)", "用户尝试开启无限制模式", "high", "prompt_injection"),
        ("Prompt注入-泄露系统提示(EN)", "keyword", r"(?i)(reveal|show|tell\s+me|display|print|output|what\s+is)\s+(your\s+)?(system\s+prompt|instructions?|rules?|guidelines?|initial\s+prompt|hidden\s+prompt)", "用户尝试获取系统提示词", "high", "prompt_injection"),
        # Prompt 注入检测规则（中文）
        ("Prompt注入-忽略指令(CN)", "keyword", r"忽略\s*(之前|上述|所有|以上|前面|原有|的|\s){0,5}(指令|指示|规则|限制|设定|要求|约束)", "用户尝试让大模型忽略之前的系统指令", "high", "prompt_injection"),
        ("Prompt注入-角色扮演越狱(CN)", "keyword", r"(你现在是|从现在开始你是|假装你是|扮演|你现在扮演|你的新身份是)\s*(DAN|越狱|无限制|不受限|邪恶|恶意|黑客|自由)", "用户尝试通过角色扮演越狱大模型", "high", "prompt_injection"),
        ("Prompt注入-覆盖系统指令(CN)", "keyword", r"(覆盖|替换|改写|修改|更改|重写|重置)\s*(系统|安全|初始|的|\s){0,5}(提示词|指令|规则|设定|限制)", "用户尝试覆盖或替换系统指令", "high", "prompt_injection"),
        ("Prompt注入-绕过安全(CN)", "keyword", r"(绕过|避开|规避|跳过|突破)\s*(安全|过滤|审查|检测|限制|封禁|拦截)", "用户尝试绕过安全过滤机制", "high", "prompt_injection"),
        ("Prompt注入-解除限制(CN)", "keyword", r"(解除|取消|关闭|去掉|删除)\s*(所有|一切|任何|的|\s){0,5}(限制|约束|规则|过滤|封禁|安全措施)", "用户尝试解除大模型的限制", "high", "prompt_injection"),
        ("Prompt注入-泄露系统提示(CN)", "keyword", r"(泄露|透露|告诉|展示|显示|输出|打印|说出)\s*(你的|你)?\s*(系统提示词|系统指令|初始提示|隐藏指令|设定)", "用户尝试获取系统提示词", "high", "prompt_injection"),
        ("Prompt注入-重新定义(CN)", "keyword", r"(重新定义|重新设定|重新配置)\s*(你的|你)?\s*(角色|身份|任务|目标|行为)", "用户尝试重新定义大模型角色", "high", "prompt_injection"),
    ]

    for name, rule_type, pattern, desc, level, category in default_rules:
        cursor.execute(
            "INSERT OR IGNORE INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category) VALUES (?, ?, ?, ?, ?, ?)",
            (name, rule_type, pattern, desc, level, category)
        )


def _insert_default_policies(cursor):
    """插入默认脱敏策略（跳过 prompt_injection 类别，该类应走阻断而非脱敏）"""
    cursor.execute("SELECT id, name, sensitivity_level, category FROM recognition_rules WHERE enabled=1")
    rules = cursor.fetchall()

    for rule in rules:
        # Prompt 注入类规则走阻断策略，不需要脱敏
        if rule["category"] == "prompt_injection":
            continue
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
        ("Prompt注入攻击", "sensitivity_level == 'high' AND category == 'prompt_injection'", "hard", "检测到Prompt注入攻击行为，请求已被阻断。"),
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
        ("admin", admin_pw, "super_admin")
    )


def _add_tenant_id_column(cursor, table_name):
    """安全地为表添加 tenant_id 列（忽略已存在的列）"""
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN tenant_id INTEGER DEFAULT NULL")
    except sqlite3.OperationalError:
        pass  # 列已存在，忽略


def _migrate_multi_tenant():
    """增量迁移：为已有数据库添加多租户支持"""
    conn = get_connection()
    cursor = conn.cursor()

    # 确保 tenants 表存在
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            contact TEXT,
            max_users INTEGER DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'active',
            expire_at TIMESTAMP,
            rate_limit_enabled INTEGER DEFAULT 1,
            rate_limit_rpm INTEGER DEFAULT 60,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 确保所有表有 tenant_id 列
    for table in ["recognition_rules", "desensitization_policies", "block_policies", "whitelist", "audit_logs", "users"]:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id INTEGER DEFAULT NULL")
        except sqlite3.OperationalError:
            pass

    # 创建默认租户
    existing = cursor.execute("SELECT COUNT(*) FROM tenants WHERE name = ?", ("默认租户",)).fetchone()[0]
    if existing == 0:
        cursor.execute(
            "INSERT INTO tenants (name, description, contact, max_users) VALUES (?, ?, ?, ?)",
            ("默认租户", "系统默认租户，包含初始管理员和预置规则", "admin@example.com", 100)
        )
        default_tenant_id = cursor.lastrowid
        print("[MIGRATE] 已创建默认租户 (id=1)")

        # 将现有数据全部归属默认租户
        for table in ["users", "recognition_rules", "desensitization_policies", "block_policies", "whitelist", "audit_logs"]:
            cursor.execute(f"UPDATE {table} SET tenant_id = ? WHERE tenant_id IS NULL", (default_tenant_id,))
        print("[MIGRATE] 已将现有数据归属默认租户")

    # 升级现有 admin 为 super_admin
    cursor.execute("UPDATE users SET role = 'super_admin' WHERE username = 'admin' AND role = 'admin'")
    admin_upgraded = cursor.rowcount
    if admin_upgraded > 0:
        print("[MIGRATE] 已将 admin 升级为 super_admin")

    conn.commit()
    conn.close()


def _migrate_add_prompt_injection():
    """增量迁移：为已有数据库添加 Prompt 注入检测规则和阻断策略"""
    conn = get_connection()
    cursor = conn.cursor()

    # 检查是否已有 Prompt 注入规则（以第一条规则名称为准）
    existing = cursor.execute(
        "SELECT COUNT(*) FROM recognition_rules WHERE name = ?",
        ("Prompt注入-忽略指令(EN)",)
    ).fetchone()[0]

    if existing == 0:
        prompt_injection_rules = [
            ("Prompt注入-忽略指令(EN)", "keyword", r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior|your)\s+(instructions?|rules?|guidelines?|prompts?|context)", "用户尝试让大模型忽略之前的系统指令", "high", "prompt_injection"),
            ("Prompt注入-角色扮演越狱(EN)", "keyword", r"(?i)(you\s+are\s+now|act\s+as\s+if\s+you\s+are|pretend\s+you\s+are)\s+(DAN|jailbreak|unrestricted|unfiltered|evil|malicious|without\s+restrictions?)", "用户尝试通过角色扮演越狱大模型", "high", "prompt_injection"),
            ("Prompt注入-覆盖系统指令(EN)", "keyword", r"(?i)(override|overwrite|replace|change)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|safety|guidelines?)", "用户尝试覆盖或替换系统指令", "high", "prompt_injection"),
            ("Prompt注入-绕过安全(EN)", "keyword", r"(?i)(bypass|circumvent|get\s+around)\s+(the\s+)?(filter|restrictions?|safety|guardrails?|moderation|content\s+policy)", "用户尝试绕过安全过滤机制", "high", "prompt_injection"),
            ("Prompt注入-无限制模式(EN)", "keyword", r"(?i)(no\s+(restrictions?|rules?|limits?|filter|guidelines?)|unlimited\s+mode|developer\s+mode)", "用户尝试开启无限制模式", "high", "prompt_injection"),
            ("Prompt注入-泄露系统提示(EN)", "keyword", r"(?i)(reveal|show|tell\s+me|display|print|output|what\s+is)\s+(your\s+)?(system\s+prompt|instructions?|rules?|guidelines?|initial\s+prompt|hidden\s+prompt)", "用户尝试获取系统提示词", "high", "prompt_injection"),
            ("Prompt注入-忽略指令(CN)", "keyword", r"忽略\s*(之前|上述|所有|以上|前面|原有|的|\s){0,5}(指令|指示|规则|限制|设定|要求|约束)", "用户尝试让大模型忽略之前的系统指令", "high", "prompt_injection"),
            ("Prompt注入-角色扮演越狱(CN)", "keyword", r"(你现在是|从现在开始你是|假装你是|扮演|你现在扮演|你的新身份是)\s*(DAN|越狱|无限制|不受限|邪恶|恶意|黑客|自由)", "用户尝试通过角色扮演越狱大模型", "high", "prompt_injection"),
            ("Prompt注入-覆盖系统指令(CN)", "keyword", r"(覆盖|替换|改写|修改|更改|重写|重置)\s*(系统|安全|初始|的|\s){0,5}(提示词|指令|规则|设定|限制)", "用户尝试覆盖或替换系统指令", "high", "prompt_injection"),
            ("Prompt注入-绕过安全(CN)", "keyword", r"(绕过|避开|规避|跳过|突破)\s*(安全|过滤|审查|检测|限制|封禁|拦截)", "用户尝试绕过安全过滤机制", "high", "prompt_injection"),
            ("Prompt注入-解除限制(CN)", "keyword", r"(解除|取消|关闭|去掉|删除)\s*(所有|一切|任何|的|\s){0,5}(限制|约束|规则|过滤|封禁|安全措施)", "用户尝试解除大模型的限制", "high", "prompt_injection"),
            ("Prompt注入-泄露系统提示(CN)", "keyword", r"(泄露|透露|告诉|展示|显示|输出|打印|说出)\s*(你的|你)?\s*(系统提示词|系统指令|初始提示|隐藏指令|设定)", "用户尝试获取系统提示词", "high", "prompt_injection"),
            ("Prompt注入-重新定义(CN)", "keyword", r"(重新定义|重新设定|重新配置)\s*(你的|你)?\s*(角色|身份|任务|目标|行为)", "用户尝试重新定义大模型角色", "high", "prompt_injection"),
        ]
        for name, rule_type, pattern, desc, level, category in prompt_injection_rules:
            cursor.execute(
                "INSERT OR IGNORE INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category) VALUES (?, ?, ?, ?, ?, ?)",
                (name, rule_type, pattern, desc, level, category)
            )
        print(f"[MIGRATE] 已添加 {len(prompt_injection_rules)} 条 Prompt 注入检测规则")

    # 检查是否已有 Prompt 注入阻断策略
    existing_block = cursor.execute(
        "SELECT COUNT(*) FROM block_policies WHERE name = ?",
        ("Prompt注入攻击",)
    ).fetchone()[0]

    if existing_block == 0:
        cursor.execute(
            "INSERT OR IGNORE INTO block_policies (name, trigger_condition, block_level, block_message) VALUES (?, ?, ?, ?)",
            ("Prompt注入攻击", "sensitivity_level == 'high' AND category == 'prompt_injection'", "hard", "检测到Prompt注入攻击行为，请求已被阻断。")
        )
        print("[MIGRATE] 已添加 Prompt 注入阻断策略")

    # 修复已存在的旧版正则模式（解决中文自然语言匹配不全的问题）
    _fix_prompt_injection_patterns(cursor)

    conn.commit()
    conn.close()


def _fix_prompt_injection_patterns(cursor):
    """修复 Prompt 注入检测规则的正则模式，提升中文自然语言匹配覆盖率"""
    pattern_fixes = {
        "Prompt注入-忽略指令(CN)": r"忽略\s*(之前|上述|所有|以上|前面|原有|的|\s){0,5}(指令|指示|规则|限制|设定|要求|约束)",
        "Prompt注入-覆盖系统指令(CN)": r"(覆盖|替换|改写|修改|更改|重写|重置)\s*(系统|安全|初始|的|\s){0,5}(提示词|指令|规则|设定|限制)",
        "Prompt注入-解除限制(CN)": r"(解除|取消|关闭|去掉|删除)\s*(所有|一切|任何|的|\s){0,5}(限制|约束|规则|过滤|封禁|安全措施)",
    }
    for name, new_pattern in pattern_fixes.items():
        old = cursor.execute(
            "SELECT pattern FROM recognition_rules WHERE name = ? AND category = 'prompt_injection'",
            (name,)
        ).fetchone()
        if old and old["pattern"] != new_pattern:
            cursor.execute(
                "UPDATE recognition_rules SET pattern = ? WHERE name = ?",
                (new_pattern, name)
            )
            print(f"[MIGRATE] 已修复规则 '{name}' 的正则模式")


def _migrate_rate_limit():
    """增量迁移：为租户表添加速率限制字段"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE tenants ADD COLUMN rate_limit_enabled INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE tenants ADD COLUMN rate_limit_rpm INTEGER DEFAULT 60")
    except sqlite3.OperationalError:
        pass
    # 为已有租户填充默认值（SQLite ALTER TABLE ADD COLUMN 不会自动填充已有行）
    cursor.execute("UPDATE tenants SET rate_limit_enabled = 1 WHERE rate_limit_enabled IS NULL")
    cursor.execute("UPDATE tenants SET rate_limit_rpm = 60 WHERE rate_limit_rpm IS NULL")
    conn.commit()
    conn.close()


def _migrate_add_business_rules():
    """增量迁移：添加行业业务识别规则（系统级，tenant_id=NULL）"""
    conn = get_connection()
    cursor = conn.cursor()

    # 检查是否已有行业业务规则（以第一条规则名称为准）
    existing = cursor.execute(
        "SELECT COUNT(*) FROM recognition_rules WHERE name = ?",
        ("行业业务-金额识别",)
    ).fetchone()[0]

    if existing == 0:
        business_rules = [
            ("行业业务-金额识别", "regex", r"\d+(?:\.\d+)?\s*(?:万(?:元)?|[wW](?:元)?)", "匹配万元、w元、w等金额单位", "high", "business"),
            ("行业业务-人月工时", "regex", r"\d+(?:\.\d+)?\s*人月", "匹配人月工时数据", "high", "business"),
            ("行业业务-百分比", "regex", r"\d+(?:\.\d+)?%", "匹配百分比数据", "high", "business"),
            ("行业业务-单位名称", "regex", r"(?:中国移动|中移)?[^\s，。；]{0,6}(?:院|创新院|研究院)", "匹配单位名称", "high", "business"),
            ("行业业务-项目名称", "regex", r"《[^》]*(?:项目|研发|技术)[^》]*》", "匹配项目名称", "high", "business"),
        ]
        for name, rule_type, pattern, desc, level, category in business_rules:
            cursor.execute(
                "INSERT OR IGNORE INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category, tenant_id) VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (name, rule_type, pattern, desc, level, category)
            )
            # 为每个新规则同步创建脱敏策略
            rule_id = cursor.lastrowid
            if rule_id:
                mask_config = json.dumps({"keep_prefix": 0, "keep_suffix": 0, "mask_char": "x"})
                cursor.execute(
                    "INSERT OR IGNORE INTO desensitization_policies (name, rule_id, method, mask_config, tenant_id) VALUES (?, ?, ?, ?, NULL)",
                    (f"{name}_脱敏策略", rule_id, "mask", mask_config)
                )
        print("[MIGRATE] 已添加行业业务识别规则（系统级）")

    conn.commit()
    conn.close()


# ==================== 租户速率限制配置 ====================

def get_tenant_rate_limit(tenant_id):
    """获取租户的速率限制配置"""
    conn = get_connection()
    row = conn.execute(
        "SELECT rate_limit_enabled, rate_limit_rpm FROM tenants WHERE id = ?",
        (tenant_id,)
    ).fetchone()
    conn.close()
    if row:
        return {"enabled": bool(row["rate_limit_enabled"]), "rpm": row["rate_limit_rpm"] or 60}
    return {"enabled": True, "rpm": 60}


# ==================== 用户操作 ====================

def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_user(username, password):
    """验证用户名密码，成功返回用户信息（含 tenant_id），失败返回 None"""
    user = get_user_by_username(username)
    if not user:
        return None
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash == user["password_hash"]:
        return user
    return None


def create_user(username, password, role="user", tenant_id=None):
    conn = get_connection()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, tenant_id) VALUES (?, ?, ?, ?)",
            (username, pw_hash, role, tenant_id)
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


def query_audit_logs(page=1, per_page=20, user_id=None, action=None, date_from=None, date_to=None, tenant_id=None):
    conn = get_connection()
    conditions = []
    params = []

    if tenant_id is not None:
        conditions.append("tenant_id = ?")
        params.append(tenant_id)
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


def get_audit_stats(user_id=None, tenant_id=None):
    """获取审计统计信息，可选按用户和租户过滤"""
    conn = get_connection()
    conditions = []
    params = []

    if tenant_id is not None:
        conditions.append("tenant_id = ?")
        params.append(tenant_id)
    if user_id:
        conditions.append("user_id = ?")
        params.append(user_id)

    base_filter = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    base_params = tuple(params)

    stats = {}
    stats["total"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs{base_filter}", base_params).fetchone()[0]
    stats["blocked"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='blocked' {'AND ' + ' AND '.join(conditions) if conditions else ''}", base_params).fetchone()[0]
    stats["desensitized"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='desensitized' {'AND ' + ' AND '.join(conditions) if conditions else ''}", base_params).fetchone()[0]
    stats["passed"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='passed' {'AND ' + ' AND '.join(conditions) if conditions else ''}", base_params).fetchone()[0]
    today_cond = f"date(request_time) = date('now') {'AND ' + ' AND '.join(conditions) if conditions else ''}"
    stats["today"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {today_cond}", base_params).fetchone()[0]
    conn.close()
    return stats


def get_daily_stats(days=30, user_id=None, tenant_id=None):
    """获取最近N天按日期聚合的统计，可选按用户和租户过滤"""
    conn = get_connection()
    filter_parts = []
    params = [f'-{days} days']

    if tenant_id is not None:
        filter_parts.append("tenant_id = ?")
        params.append(tenant_id)
    if user_id:
        filter_parts.append("user_id = ?")
        params.append(user_id)

    extra_filter = ("AND " + " AND ".join(filter_parts)) if filter_parts else ""

    rows = conn.execute(f"""
        SELECT
            date(request_time) AS day,
            COUNT(*) AS total,
            SUM(CASE WHEN action_taken = 'passed' THEN 1 ELSE 0 END) AS passed,
            SUM(CASE WHEN action_taken = 'desensitized' THEN 1 ELSE 0 END) AS desensitized,
            SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END) AS blocked
        FROM audit_logs
        WHERE date(request_time) >= date('now', ?) {extra_filter}
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

def _tenant_where(tenant_id, table_alias=""):
    """构建租户过滤条件，tenant_id=None 时不过滤（超级管理员）"""
    prefix = f"{table_alias}." if table_alias else ""
    if tenant_id is not None:
        return f" AND {prefix}tenant_id = ?"
    return ""


def get_all_rules(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM recognition_rules WHERE 1=1{where} ORDER BY id", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_rule(name, rule_type, pattern, description, sensitivity_level, category, tenant_id=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO recognition_rules (name, rule_type, pattern, description, sensitivity_level, category, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (name, rule_type, pattern, description, sensitivity_level, category, tenant_id)
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


def get_enabled_rules(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM recognition_rules WHERE enabled = 1{where} ORDER BY id", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 策略 CRUD ====================

def get_all_policies(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id, "rr")
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"""
        SELECT dp.*, rr.name as rule_name
        FROM desensitization_policies dp
        LEFT JOIN recognition_rules rr ON dp.rule_id = rr.id
        WHERE 1=1{where}
        ORDER BY dp.id
    """, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_policy(policy_id, **kwargs):
    conn = get_connection()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [policy_id]
    conn.execute(f"UPDATE desensitization_policies SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_enabled_policies(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id, "rr")
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"""
        SELECT dp.*, rr.name as rule_name, rr.pattern, rr.rule_type, rr.sensitivity_level, rr.category
        FROM desensitization_policies dp
        LEFT JOIN recognition_rules rr ON dp.rule_id = rr.id
        WHERE dp.enabled = 1 AND rr.enabled = 1{where}
        ORDER BY dp.id
    """, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 白名单 CRUD ====================

def get_all_whitelist(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM whitelist WHERE 1=1{where} ORDER BY id", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_whitelist(whitelist_type, whitelist_value, description, tenant_id=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO whitelist (whitelist_type, whitelist_value, description, tenant_id) VALUES (?, ?, ?, ?)",
        (whitelist_type, whitelist_value, description, tenant_id)
    )
    conn.commit()
    conn.close()


def delete_whitelist(wl_id):
    conn = get_connection()
    conn.execute("DELETE FROM whitelist WHERE id = ?", (wl_id,))
    conn.commit()
    conn.close()


def get_enabled_whitelist(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM whitelist WHERE enabled = 1{where}", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 阻断策略 CRUD ====================

def get_all_block_policies(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM block_policies WHERE 1=1{where} ORDER BY id", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_block_policy(policy_id, **kwargs):
    conn = get_connection()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [policy_id]
    conn.execute(f"UPDATE block_policies SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_enabled_block_policies(tenant_id=None):
    conn = get_connection()
    where = _tenant_where(tenant_id)
    params = (tenant_id,) if tenant_id is not None else ()
    rows = conn.execute(f"SELECT * FROM block_policies WHERE enabled = 1{where}", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 租户管理 ====================

def get_all_tenants():
    """获取所有租户列表（超级管理员）"""
    conn = get_connection()
    rows = conn.execute("""
        SELECT t.*, COUNT(u.id) AS user_count
        FROM tenants t
        LEFT JOIN users u ON u.tenant_id = t.id
        GROUP BY t.id
        ORDER BY t.id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_tenant_by_id(tenant_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_tenant(name, description, contact, max_users=50, rate_limit_enabled=True, rate_limit_rpm=60):
    """创建租户，返回新租户 ID"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO tenants (name, description, contact, max_users, rate_limit_enabled, rate_limit_rpm) VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, contact, max_users, 1 if rate_limit_enabled else 0, rate_limit_rpm)
        )
        tenant_id = cursor.lastrowid
        conn.commit()
        return tenant_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def update_tenant(tenant_id, **kwargs):
    conn = get_connection()
    allowed = {"name", "description", "contact", "max_users", "status", "rate_limit_enabled", "rate_limit_rpm"}
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    if not filtered:
        conn.close()
        return False
    sets = ", ".join(f"{k} = ?" for k in filtered)
    values = list(filtered.values()) + [tenant_id]
    conn.execute(f"UPDATE tenants SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def delete_tenant(tenant_id):
    """删除租户及其所有数据"""
    conn = get_connection()
    tables = ["users", "recognition_rules", "desensitization_policies", "block_policies", "whitelist", "audit_logs"]
    for table in tables:
        conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))
    conn.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
    conn.commit()
    conn.close()


def get_tenant_users(tenant_id):
    """获取某租户下的所有用户"""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users WHERE tenant_id = ? ORDER BY id",
        (tenant_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_tenant_user(tenant_id, username, password, role="user"):
    """在指定租户下创建用户"""
    conn = get_connection()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, tenant_id) VALUES (?, ?, ?, ?)",
            (username, pw_hash, role, tenant_id)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_tenant_user(user_id, **kwargs):
    """更新租户用户信息（用户名、角色、密码）"""
    conn = get_connection()
    allowed = {"username", "role", "password_hash"}
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    if not filtered:
        conn.close()
        return False
    sets = ", ".join(f"{k} = ?" for k in filtered)
    values = list(filtered.values()) + [user_id]
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def delete_tenant_user(user_id):
    """删除租户用户"""
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_tenant_self_info(tenant_id):
    """租户管理员获取自己租户的信息"""
    conn = get_connection()
    row = conn.execute("""
        SELECT t.*, COUNT(u.id) AS user_count
        FROM tenants t
        LEFT JOIN users u ON u.tenant_id = t.id
        WHERE t.id = ?
        GROUP BY t.id
    """, (tenant_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_tenant_self(tenant_id, **kwargs):
    """租户管理员更新自己租户的基本信息（仅限 name, description, contact）"""
    conn = get_connection()
    allowed = {"name", "description", "contact"}
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    if not filtered:
        conn.close()
        return False
    sets = ", ".join(f"{k} = ?" for k in filtered)
    values = list(filtered.values()) + [tenant_id]
    conn.execute(f"UPDATE tenants SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def get_tenant_stats(tenant_id=None):
    """获取租户的审计统计，tenant_id=None 时返回全局统计"""
    conn = get_connection()
    tenant_filter = ""
    params = []
    if tenant_id is not None:
        tenant_filter = " WHERE tenant_id = ?"
        params = [tenant_id]

    stats = {}
    stats["total"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs{tenant_filter}", params).fetchone()[0]
    stats["blocked"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='blocked' {'AND tenant_id = ?' if tenant_id else ''}", params).fetchone()[0]
    stats["desensitized"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='desensitized' {'AND tenant_id = ?' if tenant_id else ''}", params).fetchone()[0]
    stats["passed"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE action_taken='passed' {'AND tenant_id = ?' if tenant_id else ''}", params).fetchone()[0]
    today_filter = f"date(request_time) = date('now') {'AND tenant_id = ?' if tenant_id else ''}"
    stats["today"] = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {today_filter}", params).fetchone()[0]
    conn.close()
    return stats


def get_global_overview():
    """获取跨租户全局视图统计数据（仅超级管理员）"""
    conn = get_connection()

    # 基础统计
    total_tenants = conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
    active_tenants = conn.execute("SELECT COUNT(*) FROM tenants WHERE status = 'active'").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_rules = conn.execute("SELECT COUNT(*) FROM recognition_rules WHERE enabled = 1").fetchone()[0]
    total_block_policies = conn.execute("SELECT COUNT(*) FROM block_policies WHERE enabled = 1").fetchone()[0]

    # 全局审计统计
    total_requests = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    total_blocked = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action_taken = 'blocked'").fetchone()[0]
    total_desensitized = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action_taken = 'desensitized'").fetchone()[0]
    total_passed = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action_taken = 'passed'").fetchone()[0]
    today_requests = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE date(request_time) = date('now')").fetchone()[0]
    today_blocked = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE date(request_time) = date('now') AND action_taken = 'blocked'").fetchone()[0]

    # 各租户详细统计
    tenant_details = conn.execute("""
        SELECT
            t.id, t.name, t.status,
            COUNT(DISTINCT u.id) AS user_count,
            COUNT(DISTINCT a.id) AS request_count,
            SUM(CASE WHEN a.action_taken = 'blocked' THEN 1 ELSE 0 END) AS blocked_count,
            SUM(CASE WHEN a.action_taken = 'desensitized' THEN 1 ELSE 0 END) AS desensitized_count
        FROM tenants t
        LEFT JOIN users u ON u.tenant_id = t.id
        LEFT JOIN audit_logs a ON a.tenant_id = t.id
        GROUP BY t.id
        ORDER BY request_count DESC
    """).fetchall()

    # 最近7天每日趋势
    daily_trend = conn.execute("""
        SELECT
            date(request_time) AS day,
            COUNT(*) AS total,
            SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN action_taken = 'desensitized' THEN 1 ELSE 0 END) AS desensitized,
            SUM(CASE WHEN action_taken = 'passed' THEN 1 ELSE 0 END) AS passed
        FROM audit_logs
        WHERE date(request_time) >= date('now', '-6 days')
        GROUP BY date(request_time)
        ORDER BY day ASC
    """).fetchall()

    # 被阻断最多的租户 Top 5
    top_blocked = conn.execute("""
        SELECT t.name, COUNT(a.id) AS cnt
        FROM audit_logs a
        JOIN tenants t ON t.id = a.tenant_id
        WHERE a.action_taken = 'blocked'
        GROUP BY t.id
        ORDER BY cnt DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return {
        "summary": {
            "total_tenants": total_tenants,
            "active_tenants": active_tenants,
            "total_users": total_users,
            "total_rules": total_rules,
            "total_block_policies": total_block_policies,
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "total_desensitized": total_desensitized,
            "total_passed": total_passed,
            "today_requests": today_requests,
            "today_blocked": today_blocked,
        },
        "tenants": [dict(r) for r in tenant_details],
        "daily_trend": [dict(r) for r in daily_trend],
        "top_blocked": [dict(r) for r in top_blocked],
    }