#!/usr/bin/env python3
"""Ротация логов: удаление старых и больших файлов."""

import os
import time
from pathlib import Path

REPORTS_DIR = Path("./agent_reports")
MAX_AGE_SEC = 3600
MAX_SIZE = 10 * 1024 * 1024


def cleanup() -> int:
    deleted = 0
    if not REPORTS_DIR.exists():
        return 0
    now = time.time()
    for f in REPORTS_DIR.glob("raw_*.log"):
        age = now - f.stat().st_mtime
        size = f.stat().st_size
        if age > MAX_AGE_SEC or size > MAX_SIZE:
            f.unlink()
            deleted += 1
    return deleted