"""Исполнение команд в Docker-песочнице."""

import subprocess
from datetime import datetime
from pathlib import Path

CONTAINER = "security-agent"
REPORTS_DIR = Path("./agent_reports")


def execute(argv: list, timeout: int = 30) -> dict:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = REPORTS_DIR / f"raw_{ts}.log"
    docker_argv = ["docker", "exec", CONTAINER] + argv

    try:
        result = subprocess.run(
            docker_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, code = "", f"TIMEOUT {timeout}s", -1
    except FileNotFoundError:
        stdout, stderr, code = "", "Docker not found", -2
    except RuntimeError as e:
        stdout, stderr, code = "", str(e), -3

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        f.write(f"Command: {' '.join(docker_argv)}\n")
        f.write(f"Exit: {code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n")

    return {"stdout": stdout, "stderr": stderr, "exit_code": code, "log_path": str(log_path)}