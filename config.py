"""配置模块"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "data_protection.db")

# 代理网关配置
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 9090
MANAGEMENT_PORT = 5000

# 默认上游LLM API地址（可被代理请求的Header覆盖）
DEFAULT_UPSTREAM_URL = "https://api.openai.com/v1/chat/completions"

# 性能配置
MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024  # 10MB
REQUEST_TIMEOUT = 60  # 秒

# 审计日志保留天数
AUDIT_LOG_RETENTION_DAYS = 180

# 脱敏密钥（生产环境应使用KMS）
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "llm-data-protection-key-2026")