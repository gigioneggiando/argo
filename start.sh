#!/usr/bin/env bash
# Argo launcher (macOS / Linux / Git Bash).
# Starts the web app and opens it in your browser.
cd "$(dirname "$0")" || exit 1
echo "Starting the Argo web app at http://127.0.0.1:8000 ..."
echo "(Keep this window open. Ctrl+C to stop the server.)"
exec python -m argo.cli serve --open
