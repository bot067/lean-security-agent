#!/usr/bin/env python3
"""Lean Security Agent — точка входа."""

import sys
from orchestrator.session import AgentSession

def main():
    task = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    if not task:
        task = input("task: ").strip()
    if not task:
        return

    session = AgentSession()
    session.run(task)

if __name__ == "__main__":
    main()