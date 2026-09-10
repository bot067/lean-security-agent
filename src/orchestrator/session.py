"""Сессия агента: основной цикл генерации, валидации, исполнения."""

import json
import os
from collections import deque
from pathlib import Path
from typing import Optional

import urllib.request
import urllib.error

from src.validator.parser import parse_tool_call
from src.validator.policy import Policy
from src.orchestrator.pruner import prune
from src.executor.sandbox import execute
from src.utils.logger import log

LLM_URL = os.getenv("LLM_URL", "http://127.0.0.1:1234/v1/chat/completions")
LLM_MODEL = os.getenv("LLM_MODEL", "huihui-qwen3.5-9b-claude-4.6-opus-abliterated-heretic")

MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "50"))
MAX_CONTEXT = int(os.getenv("MAX_CONTEXT", "4096"))
MAX_LOOP = int(os.getenv("MAX_LOOP_REPEATS", "3"))
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "10"))

SYSTEM_PROMPT = """You are a security testing agent inside an isolated Docker container.
Target: 172.20.0.10:3000 (Juice Shop, Node.js + Angular web app).

Your ONLY tool is run_command. Output one JSON block per step.

Examples:
<tool_call>{"tool":"run_command","argv":["curl","-sI","http://172.20.0.10:3000"],"timeout_seconds":15}</tool_call>
<tool_call>{"tool":"run_command","argv":["ffuf","-u","http://172.20.0.10:3000/FUZZ","-w","/usr/share/wordlists/dirb/common.txt","-mc","200,301","-c","-t","20"],"timeout_seconds":120}</tool_call>

Rules:
- tool MUST be "run_command"
- argv is a JSON array of strings
- timeout_seconds max = 120
- No access to internet or host
- Do not repeat the same command more than twice"""


class AgentSession:
    def __init__(self):
        self.policy = Policy()
        self.cmd_history: deque = deque(maxlen=MAX_LOOP)
        self.findings: set = set()
        self.total_tokens = 0

    def query_llm(self, messages: list) -> Optional[dict]:
        for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            os.environ.pop(var, None)

        payload = json.dumps({
            "model": LLM_MODEL,
            "messages": messages,
            "temperature": 0.05,
            "max_tokens": 1024,
        }).encode()

        req = urllib.request.Request(
            LLM_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            resp = urllib.request.urlopen(req, timeout=180)
            return json.loads(resp.read().decode())
        except Exception as e:
            log(f"LLM error: {e}", "ERROR")
            return None

    def _trim(self, messages: list) -> list:
        size = len(json.dumps(messages))
        if size // 4 <= MAX_CONTEXT:
            return messages
        trimmed, count = [], 0
        for m in messages:
            if m.get("role") == "tool":
                count += 1
                trimmed.append({"role": "tool", "content": f"[Tool executed. Count: {count}]"})
            else:
                trimmed.append(m)
        while len(trimmed) > 2 and len(json.dumps(trimmed)) // 4 > MAX_CONTEXT:
            trimmed.pop(1)
        return trimmed

    def _detect_loop(self, argv: tuple) -> bool:
        self.cmd_history.append(argv)
        if len(self.cmd_history) < MAX_LOOP:
            return False
        return len(set(map(tuple, list(self.cmd_history)[-MAX_LOOP:]))) == 1

    def _check_findings(self, text: str, output: str):
        combined = (text + " " + output.get("stdout", "")).lower()
        for kw, name in [
            ("sql injection", "SQL Injection"),
            ("xss", "XSS"),
            ("jwt", "JWT Issue"),
            ("401", "Access Control"),
            ("403", "Access Control"),
            ("cors", "CORS Misconfiguration"),
            ("directory listing", "Directory Listing"),
        ]:
            if kw in combined and name not in self.findings:
                self.findings.add(name)
                log(f"FINDING: {name}", "WARN")

    def run(self, task: str):
        log(f"Starting session | model: {LLM_MODEL}")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ]

        for step in range(1, MAX_ITERATIONS + 1):
            if len(self.findings) >= MAX_FINDINGS:
                log(f"Stopping: {MAX_FINDINGS} findings reached", "INFO")
                break

            messages = self._trim(messages)

            if step % 5 == 0:
                pct = len(json.dumps(messages)) // 4 / MAX_CONTEXT * 100
                log(f"iter={step} tokens={self.total_tokens} findings={len(self.findings)} ctx={pct:.0f}%", "METRIC")

            resp = self.query_llm(messages)
            if not resp:
                break

            content = (resp.get("choices") or [{}])[0].get("message", {}).get("content", "")
            if not content:
                log("Empty response", "ERROR")
                break

            usage = resp.get("usage", {})
            self.total_tokens += usage.get("total_tokens", 0)

            cmd = parse_tool_call(content)
            if not cmd:
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "Output a valid JSON block with tool='run_command' and argv array"})
                continue

            argv = cmd.get("argv", [])
            if self._detect_loop(tuple(argv)):
                log(f"Loop detected: same command {MAX_LOOP}x, stopping", "WARN")
                break

            valid, reason = self.policy.validate(argv)
            if not valid:
                log(f"Rejected: {reason}", "WARN")
                result = {"stdout": "", "stderr": f"REJECTED: {reason}", "exit_code": -1, "log_path": ""}
            else:
                log(f"Exec: {' '.join(argv)}")
                result = execute(argv, cmd.get("timeout_seconds", 30))

            self._check_findings(content, result)
            tool_output = prune(result)

            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "tool", "content": tool_output})
            log(f"exit={result['exit_code']} out={len(result.get('stdout',''))}b")

        self._report()

    def _report(self):
        print(f"\n{'='*50}")
        print("SESSION COMPLETE")
        print(f"{'='*50}")
        print(f"iterations: {len(self.cmd_history)}")
        print(f"tokens: {self.total_tokens}")
        print(f"findings: {len(self.findings)}")
        for f in sorted(self.findings):
            print(f"  * {f}")
        print(f"{'='*50}")