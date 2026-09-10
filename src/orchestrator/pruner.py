"""Smart pruner: сокращает вывод команд до безопасного размера."""

MAX_STDOUT_CHARS = 800
MAX_STDERR_CHARS = 200
MAX_LINES = 100  # 50 head + 50 tail


def prune(result: dict) -> str:
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    code = result.get("exit_code", 0)
    log_path = result.get("log_path", "")

    lines = stdout.split("\n")
    if len(lines) > MAX_LINES:
        head = "\n".join(lines[:50])
        tail = "\n".join(lines[-50:])
        stdout = f"{head}\n... [обрезано: {len(lines)} строк] ...\n{tail}"
    elif len(stdout) > MAX_STDOUT_CHARS:
        stdout = stdout[:MAX_STDOUT_CHARS] + f"\n... (обрезано, {len(stdout)} символов)"

    if len(stderr) > MAX_STDERR_CHARS:
        stderr = stderr[-MAX_STDERR_CHARS:]

    meta = f"\n[Лог: {log_path}]" if log_path else ""

    return (
        f'<tool_output status="{code}">\n'
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}{meta}\n"
        f"</tool_output>"
    )