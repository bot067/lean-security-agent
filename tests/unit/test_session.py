"""
Тесты парсера и сессии.
Проверяет: parse_tool_call, _trim, основные циклы сессии.
"""
import pytest


class TestParser:
    """Тесты парсера tool_call из ответа LLM."""

    def test_parse_xml_block(self):
        from src.validator.parser import parse_tool_call
        text = '<tool_call>{"tool": "run_command", "argv": ["curl", "-s", "http://target"], "timeout_seconds": 15}</tool_call>'
        result = parse_tool_call(text)
        assert result is not None
        assert result["tool"] == "run_command"
        assert result["argv"] == ["curl", "-s", "http://target"]

    def test_parse_fenced_json(self):
        from src.validator.parser import parse_tool_call
        text = '```json\n{"tool": "run_command", "argv": ["nmap", "-sV", "10.0.0.1"], "timeout_seconds": 30}\n```'
        result = parse_tool_call(text)
        assert result is not None
        assert result["tool"] == "run_command"

    def test_parse_bare_json(self):
        from src.validator.parser import parse_tool_call
        text = 'Some text {"tool": "run_command", "argv": ["ls", "-la"], "timeout_seconds": 10} trailing text'
        result = parse_tool_call(text)
        assert result is not None
        assert result["argv"] == ["ls", "-la"]

    def test_parse_no_match(self):
        from src.validator.parser import parse_tool_call
        result = parse_tool_call("Just some text without any tool call")
        assert result is None

    def test_parse_wrong_tool(self):
        from src.validator.parser import parse_tool_call
        text = '<tool_call>{"tool": "other_tool", "argv": ["ls"]}</tool_call>'
        result = parse_tool_call(text)
        assert result is not None
        assert result["tool"] == "other_tool"


class TestSessionTrim:
    """Тесты усечения контекста (AgentSession._trim)."""

    def test_trim_replaces_tool_messages(self, session):
        # Messages must exceed ~4096*4 bytes to trigger trim
        long_content = "data " * 4000  # ~20k chars, exceeds 4096*4 threshold
        messages = [
            {"role": "system", "content": "You are an agent."},
            {"role": "user", "content": "scan target"},
            {"role": "assistant", "content": "response"},
            {"role": "tool", "content": long_content},
        ]
        trimmed = session._trim(messages)
        for m in trimmed:
            if m["role"] == "tool":
                # Content should be shortened
                assert len(m["content"]) < len(long_content), (
                    f"Tool content not reduced: {len(m['content'])} >= {len(long_content)}"
                )
                break

    def test_trim_preserves_system_user(self, session):
        messages = [
            {"role": "system", "content": "You are an agent."},
            {"role": "user", "content": "scan target"},
            {"role": "tool", "content": "x" * 10000},  # очень большой
        ]
        trimmed = session._trim(messages)
        assert len(trimmed) >= 2, "System + user should survive"
        assert trimmed[0]["role"] == "system"
        assert trimmed[1]["role"] == "user"

    def test_trim_under_limit_unchanged(self, session):
        messages = [
            {"role": "system", "content": "short"},
            {"role": "user", "content": "short"},
        ]
        trimmed = session._trim(messages)
        assert len(trimmed) == 2


class TestSessionFindings:
    """Тесты детекции findings из вывода."""

    def test_detect_xss(self, session):
        session._check_findings(
            "Found XSS vulnerability in search endpoint",
            {"stdout": "payload reflected in DOM"}
        )
        assert "XSS" in session.findings

    def test_detect_sqli(self, session):
        session._check_findings(
            "SQL injection in login form",
            {"stdout": "error: syntax error"}
        )
        assert "SQL Injection" in session.findings

    def test_detect_jwt(self, session):
        session._check_findings(
            "JWT token decoded",
            {"stdout": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"}
        )
        assert "JWT Issue" in session.findings

    def test_detect_no_false_positive(self, session):
        session._check_findings(
            "Everything looks clean",
            {"stdout": "200 OK"}
        )
        assert len(session.findings) == 0