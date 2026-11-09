"""Minimal stdio MCP server exposing Argo's validated Vibe artifact writer.

The server accepts only ``write_file`` and delegates path policy, JSON validation, and atomic
replacement to the same toolbox used by ``mistral-api``. It is launched by the isolated Vibe
session with the session scratch directory as its only write root.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .mistral_api import Toolbox
from .tool_errors import ToolError


_TOOL = {
    "name": "write_file",
    "description": (
        "Create or overwrite a file inside Argo's session working directory. JSON files are "
        "validated before writing; if validation fails, correct the content and retry."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
}


def _response(request_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _handle(request: dict, toolbox: Toolbox) -> dict | None:
    method = request.get("method")
    request_id = request.get("id")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        params = request.get("params")
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        version = requested if isinstance(requested, str) else "2024-11-05"
        return _response(request_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "argo-artifact-writer", "version": "1.0.0"},
        })
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": [_TOOL]})
    if method == "tools/call":
        params = request.get("params")
        params = params if isinstance(params, dict) else {}
        if params.get("name") != "write_file":
            message = "unknown tool; available: write_file"
            failed = True
        else:
            try:
                message = toolbox.dispatch("write_file", params.get("arguments", {}))
                failed = False
            except ToolError as exc:
                message = str(exc)
                failed = True
        result = {"content": [{"type": "text", "text": message}]}
        if failed:
            result["isError"] = True
        return _response(request_id, result)
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32601, "message": "method not found"}}


def serve(work_dir: Path) -> None:
    """Serve line-delimited MCP JSON-RPC on stdin/stdout; diagnostics never use stdout."""
    toolbox = Toolbox(repo_dir=None, work_dir=work_dir, allow_write=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}}
        else:
            response = _handle(request, toolbox) if isinstance(request, dict) else {
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request"},
            }
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    serve(args.work_dir)


if __name__ == "__main__":
    main()
