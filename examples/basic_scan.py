#!/usr/bin/env python3
"""Пример: базовое сканирование Juice Shop."""

import sys
sys.path.insert(0, ".")

from src.orchestrator.session import AgentSession

session = AgentSession()
session.run("Scan 172.20.0.10:3000 for open ports and common vulnerabilities")