"""
Тесты валидатора команд (Policy.validate).
Проверяет: whitelist бинарников, blacklist паттернов.
"""
import pytest


class TestWhitelist:
    """Тесты белого списка разрешённых бинарников."""

    def test_nmap_allowed(self, policy, valid_argv_set):
        ok, msg = policy.validate(valid_argv_set[0])
        assert ok, f"nmap should be allowed: {msg}"

    def test_curl_allowed(self, policy):
        ok, msg = policy.validate(["curl", "-s", "http://target"])
        assert ok, f"curl should be allowed: {msg}"

    def test_ffuf_allowed(self, policy):
        ok, msg = policy.validate(["ffuf", "-u", "http://target/FUZZ"])
        assert ok, f"ffuf should be allowed: {msg}"

    def test_grep_allowed(self, policy):
        ok, msg = policy.validate(["grep", "-r", "pattern", "."])
        assert ok, f"grep should be allowed: {msg}"

    def test_jq_allowed(self, policy):
        ok, msg = policy.validate(["jq", ".", "file.json"])
        assert ok, f"jq should be allowed: {msg}"

    def test_echo_allowed(self, policy):
        ok, msg = policy.validate(["echo", "hello"])
        assert ok, f"echo should be allowed: {msg}"


class TestBlacklist:
    """Тесты запрещённых бинарников и паттернов."""

    def test_chmod_blocked(self, policy, invalid_binary_set):
        ok, _ = policy.validate(invalid_binary_set[0])
        assert not ok, "chmod should be blocked"

    def test_rm_rf_blocked(self, policy):
        ok, msg = policy.validate(["rm", "-rf", "/"])
        assert not ok, f"rm -rf should be blocked: {msg}"

    def test_python_blocked(self, policy):
        ok, _ = policy.validate(["python", "-c", "print(1)"])
        assert not ok, "python should be blocked"

    def test_sh_blocked(self, policy):
        ok, _ = policy.validate(["sh", "-c", "ls"])
        assert not ok, "sh should be blocked"

    def test_bash_blocked(self, policy):
        ok, _ = policy.validate(["bash", "-c", "echo test"])
        assert not ok, "bash should be blocked"

    def test_backtick_injection(self, policy):
        ok, _ = policy.validate(["echo", "`id`"])
        assert not ok, "backticks should be blocked"

    def test_substitution_injection(self, policy):
        ok, _ = policy.validate(["echo", "$(whoami)"])
        assert not ok, "$() should be blocked"

    def test_dev_redirect(self, policy):
        ok, _ = policy.validate(["echo", "test", ">", "/dev/null"])
        assert not ok, ">/dev/ should be blocked"


class TestEdgeCases:
    """Граничные случаи."""

    def test_empty_argv(self, policy):
        ok, _ = policy.validate([])
        assert not ok, "empty argv should be rejected"

    def test_unknown_binary(self, policy):
        ok, _ = policy.validate(["unknown-tool", "--flag"])
        assert not ok, "unknown binary should be rejected"

    def test_policy_allowed_set(self, policy):
        assert "nmap" in policy.allowed
        assert "curl" in policy.allowed
        assert "ffuf" in policy.allowed
        assert "jq" in policy.allowed