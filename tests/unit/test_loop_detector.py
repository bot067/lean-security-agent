"""
Тесты детектора зацикливания (AgentSession._detect_loop).
Проверяет: 3+ одинаковых вызова подряд, нормальную последовательность.
"""
import pytest


class TestLoopDetector:
    """Тесты обнаружения зацикливания."""

    def test_three_identical_detected(self, session):
        for _ in range(3):
            session._detect_loop(("nmap", "-sV", "192.168.1.1"))
        # После 3-го добавления — петля
        assert session._detect_loop(("nmap", "-sV", "192.168.1.1")) is True

    def test_two_identical_not_detected(self, session):
        session._detect_loop(("curl", "-s", "http://target"))
        result = session._detect_loop(("curl", "-s", "http://target"))
        assert result is False  # 2 < порога 3

    def test_diverse_commands_not_detected(self, session):
        session._detect_loop(("nmap", "target1"))
        session._detect_loop(("curl", "target2"))
        session._detect_loop(("ffuf", "target3"))
        result = session._detect_loop(("nmap", "target4"))
        assert result is False

    def test_non_consecutive_duplicates_not_detected(self, session):
        session._detect_loop(("nmap", "192.168.1.1"))
        session._detect_loop(("curl", "http://target"))
        session._detect_loop(("nmap", "192.168.1.1"))
        result = session._detect_loop(("curl", "http://other"))
        assert result is False

    def test_loop_detection_breaks_after_diverse(self, session):
        for _ in range(3):
            session._detect_loop(("curl", "-s", "http://x"))
        # Петля
        assert session._detect_loop(("curl", "-s", "http://x")) is True

    def test_cmd_history_maxlen(self, session):
        """Проверяет, что история не растёт бесконечно."""
        for i in range(10):
            session._detect_loop(("nmap", str(i)))
        assert len(session.cmd_history) <= 3, f"History should be <= 3, got {len(session.cmd_history)}"