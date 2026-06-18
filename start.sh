#!/usr/bin/env bash
# Argo launcher (macOS / Linux / Git Bash).
# Starts the web app and opens it in your browser. Keep this window open; Ctrl+C to stop.
cd "$(dirname "$0")" || exit 1

# Prefer python3 (macOS/Linux often have no bare `python`); fall back to python.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Error: Python 3 not found on PATH. Install Python 3 and retry." >&2
  exit 1
fi

echo "Starting the Argo web app at http://127.0.0.1:8000 ..."
echo "(Keep this window open. Ctrl+C to stop the server.)"
exec "$PY" -m argo.cli serve --open
