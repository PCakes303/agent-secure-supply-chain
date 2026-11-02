#!/usr/bin/env python3
"""Run the local, dependency-free starter build."""
import subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for command in ([sys.executable, "tools/validate_supply_chain.py"], [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]):
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        raise SystemExit(result.returncode)
print("Starter build passed.")
