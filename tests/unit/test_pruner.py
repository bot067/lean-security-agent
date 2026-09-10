"""
Тесты Smart Pruner (prune).
Проверяет: усечение >100 строк, сохранение head/tail, метаданные, лимиты.
"""
import pytest


class TestPruner:
    """Тесты усечения длинного вывода."""

    def test_long_output_truncated(self, sample_long_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_long_result)
        lines = result.split("\n")
        # 150 строк -> должно быть усечено
        assert len(lines) < 120, f"Expected <120 lines, got {len(lines)}"

    def test_long_output_contains_first_lines(self, sample_long_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_long_result)
        assert "line_0" in result
        assert "line_1" in result

    def test_long_output_contains_last_lines(self, sample_long_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_long_result)
        assert "line_149" in result
        assert "line_148" in result

    def test_long_output_has_truncation_marker(self, sample_long_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_long_result)
        assert "обрезано" in result.lower() or "[150" in result

    def test_short_output_unchanged(self, sample_short_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_short_result)
        assert "HTTP/1.1 200 OK" in result

    def test_exactly_100_lines_not_truncated(self):
        from src.orchestrator.pruner import prune
        output = "\n".join([f"line_{i}" for i in range(100)])
        result = prune({"stdout": output, "stderr": "", "exit_code": 0, "log_path": ""})
        assert "line_0" in result
        assert "line_99" in result

    def test_101_lines_truncated(self):
        from src.orchestrator.pruner import prune
        output = "\n".join([f"line_{i}" for i in range(101)])
        result = prune({"stdout": output, "stderr": "", "exit_code": 0, "log_path": ""})
        assert "101" in result or "обрезано" in result.lower()

    def test_empty_output(self):
        from src.orchestrator.pruner import prune
        result = prune({"stdout": "", "stderr": "", "exit_code": 0, "log_path": ""})
        assert "<tool_output" in result

    def test_stderr_truncated(self):
        from src.orchestrator.pruner import prune
        long_err = "X" * 500
        result = prune({"stdout": "ok", "stderr": long_err, "exit_code": 1, "log_path": ""})
        stderr_section = result.split("stderr:\n")[1].split("\n")[0]
        assert len(stderr_section) <= 250, f"stderr too long: {len(stderr_section)}"

    def test_exit_code_in_tag(self):
        from src.orchestrator.pruner import prune
        result = prune({"stdout": "", "stderr": "", "exit_code": 7, "log_path": ""})
        assert 'status="7"' in result

    def test_log_path_in_meta(self, sample_long_result):
        from src.orchestrator.pruner import prune
        result = prune(sample_long_result)
        assert "/tmp/raw_test.log" in result or "Лог" in result