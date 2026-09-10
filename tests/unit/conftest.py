import sys
import os
from collections import deque
import pytest

# Repository root
REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
SRC_DIR = os.path.join(REPO_ROOT, "src")

# Add src/ to path so imports like "from src.orchestrator.pruner import prune" work
sys.path.insert(0, os.path.abspath(SRC_DIR))


@pytest.fixture
def sample_long_result():
    """Результат выполнения команды с длинным stdout (>100 строк)."""
    lines = "\n".join([f"line_{i}: data" for i in range(150)])
    return {
        "stdout": lines,
        "stderr": "",
        "exit_code": 0,
        "log_path": "/tmp/raw_test.log"
    }


@pytest.fixture
def sample_short_result():
    """Короткий вывод, не требующий усечения."""
    return {
        "stdout": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>OK</html>",
        "stderr": "",
        "exit_code": 0,
        "log_path": ""
    }


@pytest.fixture
def policy():
    from src.validator.policy import Policy
    return Policy()


@pytest.fixture
def valid_argv_set():
    """Набор argv, которые ДОЛЖНЫ проходить валидацию."""
    return [
        ["nmap", "-sV", "192.168.1.1"],
        ["curl", "-s", "http://target:3000/api"],
        ["ffuf", "-u", "http://target/FUZZ", "-w", "wordlist.txt"],
        ["grep", "-r", "password", "/app/reports/"],
        ["jq", ".", "report.json"],
        ["echo", "test"],
    ]


@pytest.fixture
def invalid_binary_set():
    """argv с бинарниками НЕ из allowed-списка."""
    return [
        ["chmod", "777", "/etc/passwd"],
        ["rm", "-rf", "/"],
        ["python", "-c", "print(1)"],
        ["sh", "-c", "ls"],
        ["bash", "-c", "echo test"],
    ]


@pytest.fixture
def session():
    from src.orchestrator.session import AgentSession
    return AgentSession()