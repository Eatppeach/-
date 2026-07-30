"""数据脱敏引擎 — 支持掩码、替换、加密、哈希等脱敏算法"""

import re
import json
import hashlib
import base64
from database import get_enabled_policies
from config import ENCRYPTION_KEY


class DesensitizationEngine:
    """智能数据脱敏引擎"""

    def __init__(self):
        self._policies = []
        self._compiled_rules = {}
        self._reload()

    def _reload(self):
        """从数据库重新加载脱敏策略"""
        policies = get_enabled_policies()
        self._policies = policies
        self._compiled_rules = {}
        for policy in policies:
            if policy.get("pattern") and policy.get("rule_type") == "regex":
                try:
                    self._compiled_rules[policy["rule_name"]] = re.compile(policy["pattern"], re.IGNORECASE)
                except re.error:
                    pass

    def refresh(self):
        self._reload()

    def desensitize(self, text, matches):
        """
        对文本中的敏感信息进行脱敏处理
        matches: 识别引擎返回的匹配列表
        返回脱敏后的文本
        """
        if not matches:
            return text

        # 按位置排序（从后往前替换，避免位置偏移）
        sorted_matches = sorted(matches, key=lambda m: m["position"][0], reverse=True)

        result = text
        for match in sorted_matches:
            rule_name = match["rule_name"]
            matched_text = match["matched_text"]
            start, end = match["position"]

            # 查找对应的脱敏策略
            policy = self._find_policy(rule_name)
            if not policy:
                continue

            method = policy.get("method", "mask")
            mask_config = json.loads(policy.get("mask_config", "{}"))

            desensitized = self._apply_desensitization(matched_text, method, mask_config)
            result = result[:start] + desensitized + result[end:]

        return result

    def _find_policy(self, rule_name):
        for p in self._policies:
            if p.get("rule_name") == rule_name:
                return p
        return None

    def _apply_desensitization(self, text, method, config):
        """应用脱敏算法"""
        if method == "mask":
            return self._mask(text, config)
        elif method == "replace":
            return self._replace(text, config)
        elif method == "encrypt":
            return self._encrypt(text, config)
        elif method == "hash":
            return self._hash(text, config)
        elif method == "generalize":
            return self._generalize(text, config)
        else:
            return self._mask(text, config)

    def _mask(self, text, config):
        """掩码脱敏：保留首尾N个字符，中间替换为*"""
        keep_prefix = config.get("keep_prefix", 3)
        keep_suffix = config.get("keep_suffix", 4)
        mask_char = config.get("mask_char", "*")

        if len(text) <= keep_prefix + keep_suffix:
            return mask_char * len(text)

        prefix = text[:keep_prefix]
        suffix = text[-keep_suffix:] if keep_suffix > 0 else ""
        mask_len = len(text) - keep_prefix - keep_suffix
        return prefix + mask_char * mask_len + suffix

    def _replace(self, text, config):
        """替换脱敏：用指定字符串替换"""
        replacement = config.get("replacement", "***")
        return replacement

    def _encrypt(self, text, config):
        """可逆加密脱敏（AES-256-CBC简化实现）"""
        try:
            key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import os

            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            return "[ENC:" + base64.b64encode(iv + encrypted).decode() + "]"
        except ImportError:
            # 无 pycryptodome 时回退到base64编码
            return "[ENC:" + base64.b64encode(text.encode()).decode() + "]"

    def _hash(self, text, config):
        """哈希脱敏（不可逆）"""
        algorithm = config.get("algorithm", "sha256")
        h = hashlib.new(algorithm)
        h.update(text.encode())
        return "[HASH:" + h.hexdigest()[:16] + "]"

    def _generalize(self, text, config):
        """泛化脱敏：将具体值替换为范围值"""
        # 简单实现：将数字替换为范围
        import re as re_m
        if re_m.match(r"^\d+$", text):
            num = int(text)
            step = config.get("step", 10)
            lower = (num // step) * step
            upper = lower + step
            return f"{lower}-{upper}"
        return "***"


# 全局单例
desensitization_engine = DesensitizationEngine()