"""代理网关 — 拦截大模型请求，执行安全检测与脱敏后转发"""

import json
import time
import requests
from database import add_audit_log, get_enabled_block_policies
from recognition_engine import recognition_engine
from desensitization_engine import desensitization_engine


class SecurityGateway:
    """大模型数据安全代理网关"""

    def __init__(self):
        self._block_policies = []
        self._reload()

    def _reload(self):
        self._block_policies = get_enabled_block_policies()

    def refresh(self):
        self._reload()
        recognition_engine.refresh()
        desensitization_engine.refresh()

    def process_request(self, user_input, client_ip=None, user_id=None, request_url=None):
        """
        处理大模型请求的核心流程：
        1. 识别敏感数据
        2. 检查阻断策略
        3. 执行脱敏
        4. 记录审计日志
        返回: {
            "action": "passed" | "desensitized" | "blocked",
            "block_level": "hard" | "soft" | "silent" | None,
            "block_message": str | None,
            "processed_input": str,  # 处理后的输入
            "scan_result": dict,
            "processing_time_ms": float
        }
        """
        start_time = time.time()

        # 1. 敏感数据识别
        scan_result = recognition_engine.scan(user_input, client_ip, user_id)

        # 2. 检查白名单
        if scan_result.get("whitelisted"):
            processing_time = (time.time() - start_time) * 1000
            add_audit_log(
                user_id=user_id, client_ip=client_ip,
                original_input=user_input, desensitized_input=user_input,
                model_output=None, triggered_rules=[],
                action_taken="passed", block_level=None,
                processing_time_ms=processing_time, request_url=request_url
            )
            return {
                "action": "passed",
                "block_level": None,
                "block_message": None,
                "processed_input": user_input,
                "scan_result": scan_result,
                "processing_time_ms": processing_time,
            }

        # 3. 检查阻断策略
        block_result = self._check_block(scan_result)
        if block_result["should_block"]:
            if block_result["level"] == "hard":
                # 硬阻断：直接拒绝
                processing_time = (time.time() - start_time) * 1000
                triggered_rules = [m["rule_name"] for m in scan_result["matches"]]
                add_audit_log(
                    user_id=user_id, client_ip=client_ip,
                    original_input=user_input,
                    desensitized_input=None,
                    model_output=None,
                    triggered_rules=triggered_rules,
                    action_taken="blocked",
                    block_level="hard",
                    processing_time_ms=processing_time,
                    request_url=request_url,
                )
                return {
                    "action": "blocked",
                    "block_level": "hard",
                    "block_message": block_result["message"],
                    "processed_input": None,
                    "scan_result": scan_result,
                    "processing_time_ms": processing_time,
                }
            elif block_result["level"] == "soft":
                # 软阻断：告警并记录，但仍执行脱敏后放行
                desensitized = desensitization_engine.desensitize(user_input, scan_result["matches"])
                processing_time = (time.time() - start_time) * 1000
                triggered_rules = [m["rule_name"] for m in scan_result["matches"]]
                add_audit_log(
                    user_id=user_id, client_ip=client_ip,
                    original_input=user_input,
                    desensitized_input=desensitized,
                    model_output=None,
                    triggered_rules=triggered_rules,
                    action_taken="desensitized",
                    block_level="soft",
                    processing_time_ms=processing_time,
                    request_url=request_url,
                )
                return {
                    "action": "desensitized",
                    "block_level": "soft",
                    "block_message": block_result["message"],
                    "processed_input": desensitized,
                    "scan_result": scan_result,
                    "processing_time_ms": processing_time,
                }
            else:
                # 静默阻断：脱敏后放行，不通知用户
                desensitized = desensitization_engine.desensitize(user_input, scan_result["matches"])
                processing_time = (time.time() - start_time) * 1000
                triggered_rules = [m["rule_name"] for m in scan_result["matches"]]
                add_audit_log(
                    user_id=user_id, client_ip=client_ip,
                    original_input=user_input,
                    desensitized_input=desensitized,
                    model_output=None,
                    triggered_rules=triggered_rules,
                    action_taken="desensitized",
                    block_level="silent",
                    processing_time_ms=processing_time,
                    request_url=request_url,
                )
                return {
                    "action": "desensitized",
                    "block_level": "silent",
                    "block_message": None,
                    "processed_input": desensitized,
                    "scan_result": scan_result,
                    "processing_time_ms": processing_time,
                }

        # 4. 执行脱敏
        if scan_result["has_sensitive"]:
            desensitized = desensitization_engine.desensitize(user_input, scan_result["matches"])
            processing_time = (time.time() - start_time) * 1000
            triggered_rules = [m["rule_name"] for m in scan_result["matches"]]
            add_audit_log(
                user_id=user_id, client_ip=client_ip,
                original_input=user_input,
                desensitized_input=desensitized,
                model_output=None,
                triggered_rules=triggered_rules,
                action_taken="desensitized",
                block_level=None,
                processing_time_ms=processing_time,
                request_url=request_url,
            )
            return {
                "action": "desensitized",
                "block_level": None,
                "block_message": None,
                "processed_input": desensitized,
                "scan_result": scan_result,
                "processing_time_ms": processing_time,
            }

        # 5. 无敏感信息，直接放行
        processing_time = (time.time() - start_time) * 1000
        add_audit_log(
            user_id=user_id, client_ip=client_ip,
            original_input=user_input,
            desensitized_input=user_input,
            model_output=None,
            triggered_rules=[],
            action_taken="passed",
            block_level=None,
            processing_time_ms=processing_time,
            request_url=request_url,
        )
        return {
            "action": "passed",
            "block_level": None,
            "block_message": None,
            "processed_input": user_input,
            "scan_result": scan_result,
            "processing_time_ms": processing_time,
        }

    def process_output(self, model_output, client_ip=None, user_id=None):
        """对模型输出进行安全扫描"""
        scan_result = recognition_engine.scan(model_output, client_ip, user_id)
        if scan_result["has_sensitive"]:
            return desensitization_engine.desensitize(model_output, scan_result["matches"])
        return model_output

    def _check_block(self, scan_result):
        """检查阻断策略"""
        if not scan_result["has_sensitive"]:
            return {"should_block": False, "level": None, "message": None}

        highest_block = {"should_block": False, "level": None, "message": None}
        level_priority = {"hard": 3, "soft": 2, "silent": 1}

        for policy in self._block_policies:
            if self._evaluate_condition(policy["trigger_condition"], scan_result):
                current_priority = level_priority.get(policy["block_level"], 0)
                if current_priority > level_priority.get(highest_block["level"], 0):
                    highest_block = {
                        "should_block": True,
                        "level": policy["block_level"],
                        "message": policy["block_message"],
                    }

        return highest_block

    def _evaluate_condition(self, condition, scan_result):
        """简易条件评估引擎，支持 sensitivity_level + category + match_count 组合条件"""
        try:
            ctx = {
                "sensitivity_level": scan_result.get("highest_level"),
                "match_count": scan_result.get("match_count", 0),
                "has_sensitive": scan_result.get("has_sensitive", False),
            }

            # 解析条件中的字段值
            parsed = self._parse_condition(condition)

            # 逐字段验证
            if "sensitivity_level" in parsed:
                expected_level = parsed["sensitivity_level"]
                if ctx["sensitivity_level"] != expected_level:
                    return False

            if "category" in parsed:
                expected_category = parsed["category"]
                has_category = any(
                    m["category"] == expected_category for m in scan_result.get("matches", [])
                )
                if not has_category:
                    return False

            if "match_count" in parsed:
                op, threshold = parsed["match_count"]
                if op == ">" and ctx["match_count"] <= threshold:
                    return False
                if op == ">=" and ctx["match_count"] < threshold:
                    return False

            return True
        except Exception:
            return False

    def _parse_condition(self, condition):
        """解析条件字符串，返回字段字典
        支持格式: "sensitivity_level == 'high' AND category == 'credential'"
        """
        parsed = {}
        parts = condition.split(" AND ")
        for part in parts:
            part = part.strip()
            if "==" in part:
                left, right = part.split("==", 1)
                left = left.strip()
                right = right.strip().strip("'\"")
                parsed[left] = right
            elif ">" in part:
                left, right = part.split(">", 1)
                left = left.strip()
                right = int(right.strip())
                parsed[left] = (">", right)
            elif ">=" in part:
                left, right = part.split(">=", 1)
                left = left.strip()
                right = int(right.strip())
                parsed[left] = (">=", right)
        return parsed

    def forward_to_llm(self, processed_input, upstream_url, api_key=None, model=None, stream=False, history=None):
        """将处理后的请求转发到大模型API"""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        messages = history or []
        messages.append({"role": "user", "content": processed_input})

        payload = {
            "model": model or "gpt-3.5-turbo",
            "messages": messages,
            "stream": stream,
        }

        try:
            resp = requests.post(
                upstream_url,
                headers=headers,
                json=payload,
                timeout=60,
                stream=stream,
            )
            if stream:
                return resp
            return resp.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    def stream_llm_response(self, processed_input, upstream_url, api_key=None, model=None, history=None):
        """流式转发并逐chunk对输出做安全扫描，返回生成器"""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        messages = history or []
        messages.append({"role": "user", "content": processed_input})

        payload = {
            "model": model or "gpt-3.5-turbo",
            "messages": messages,
            "stream": True,
        }

        try:
            resp = requests.post(
                upstream_url,
                headers=headers,
                json=payload,
                timeout=60,
                stream=True,
            )
            if resp.status_code != 200:
                yield f"data: {json.dumps({'error': f'Upstream returned {resp.status_code}', 'detail': resp.text[:200]})}\n\n"
                return

            accumulated = ""
            for line in resp.iter_lines():
                if not line:
                    continue
                decoded = line.decode("utf-8")
                # 透传原始 SSE 行
                yield decoded + "\n"

                # 提取 content delta 用于安全扫描
                if decoded.startswith("data: ") and decoded != "data: [DONE]":
                    try:
                        chunk = json.loads(decoded[6:])
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            accumulated += content
                    except (json.JSONDecodeError, KeyError, IndexError):
                        pass

            # 流结束后对完整输出做安全扫描
            if accumulated:
                safe_output = self.process_output(accumulated)
                if safe_output != accumulated:
                    yield f"data: {json.dumps({'warning': 'output_contains_sensitive', 'note': '模型输出中检测到敏感信息'})}\n\n"

            yield "data: [DONE]\n\n"

        except requests.RequestException as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"


# 全局单例
gateway = SecurityGateway()