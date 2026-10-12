#!/usr/bin/env bash
# One-command experiment reproduction wrapper for POSIX environments
set -euo pipefail

echo "=========================================================="
echo " Running ACIP One-Command Reproducibility Suite (POSIX)    "
echo "=========================================================="

PYTHON_BIN=".venv/bin/python"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

"$PYTHON_BIN" scripts/reproduce_results.py experiments/results

echo "Reproduction suite succeeded."
