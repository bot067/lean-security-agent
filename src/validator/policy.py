"""Политики: белый список команд и запрещённые паттерны."""

import json
import re
from pathlib import Path

DEFAULT_ALLOWED = {
    "nmap", "curl", "wget", "ffuf", "dirb", "gobuster",
    "jq", "grep", "awk", "sed", "sort", "uniq",
    "head", "tail", "cat", "ls", "pwd", "wc", "file",
    "ping", "traceroute", "dig", "host", "which",
    "date", "echo", "base64",
}

DEFAULT_FORBIDDEN = [
    r"rm\s+-rf",
    r"mkfs",
    r"dd\s+if=",
    r"chmod\s+777",
    r"curl.*\|\s*(sh|bash)",
    r"wget.*\|\s*(sh|bash)",
    r"eval\s+",
    r"source\s+",
    r"base64\s+-d.*\|",
    r">\s*/etc/",
    r">\s*/dev/",
    r"\$\(",
    r"`",
]


class Policy:
    def __init__(self, allowed: set = None, forbidden: list = None):
        self.allowed = allowed or DEFAULT_ALLOWED
        self.forbidden = forbidden or DEFAULT_FORBIDDEN

    @classmethod
    def from_files(cls, allowed_path: str, forbidden_path: str) -> "Policy":
        with open(allowed_path) as f:
            allowed = set(json.load(f)["binaries"])
        with open(forbidden_path) as f:
            forbidden = json.load(f)["patterns"]
        return cls(allowed, forbidden)

    def validate(self, argv: list) -> tuple[bool, str]:
        """True если команда разрешена."""
        tool = argv[0] if argv else ""
        if tool not in self.allowed:
            return False, f"'{tool}' не в белом списке"
        full = " ".join(argv)
        for pattern in self.forbidden:
            if re.search(pattern, full):
                return False, f"запрещённый паттерн '{pattern}'"
        return True, "OK"