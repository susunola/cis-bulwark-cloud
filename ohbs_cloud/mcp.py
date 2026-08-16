"""Minimal MCP (Model Context Protocol) extension surface.

Exposes the read-only ohbs-cloud tools over a stdio JSON-RPC exchange so an
agent / LLM host can drive assessments without reimplementing them:

    tools.list           -> the active control registry (like `ohbs-cloud list`)
    tools.scan           -> a dry-run scan plan (no cloud call)
    tools.diff           -> compare two scan JSON files (BASE CUR)
    tools.check_drift    -> regressions vs a baseline (BASE CUR)
    tools.plan           -> a dry-run hardening plan

Requests are newline-delimited JSON::

    {"id": 1, "method": "tools/list"}
    {"id": 2, "method": "tools/call", "params": {"name": "list", "arguments": {"format": "json"}}}

Responses follow JSON-RPC 2.0: `{"jsonrpc":"2.0","id":1,"result":...}` or an
`error` object. `run_stdio()` reads one request per line from stdin and writes
one response per line to stdout; it keeps running until stdin closes. No third
party dependency — the MCP client integration lives in `ohbs_cloud/mcp.py`.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

from . import get_catalog as _catalog_mod
from . import get_root as _root_mod
from . import get_selector as _selector
from . import cloud as _cloud
from .reporter import Reporter
from .schema import normalize_finding as _normalize

JSON_RPC = "2.0"

TOOLS = [
    {
        "name": "list",
        "description": "Show the control registry for the active cloud.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["json", "table", "markdown", "html"]},
                "framework": {"type": "string", "description": "nist | pci | djcp"},
            },
        },
    },
    {
        "name": "scan",
        "description": "Dry-run scan: the controls that would be assessed. Never touches the cloud.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "plan",
        "description": "Dry-run hardening plan: the stacks and controls that would be applied.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "diff",
        "description": "Compare two scan JSON files (baseline then current).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base": {"type": "string", "description": "path to baseline scan JSON"},
                "cur": {"type": "string", "description": "path to current scan JSON"},
            },
            "required": ["base", "cur"],
        },
    },
    {
        "name": "check_drift",
        "description": "Regressions of a baseline scan JSON vs a current scan JSON (now failing, were not).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base": {"type": "string"},
                "cur": {"type": "string"},
            },
            "required": ["base", "cur"],
        },
    },
]


def _result(name: str, arguments: dict) -> Any:
    """Dispatch one tool call and return its JSON-serialisable result."""
    fmt = str(arguments.get("format", "json"))
    if name == "list":
        cat = _catalog_mod()
        sel = _selector()
        if arguments.get("framework"):
            os.environ["CIS_FRAMEWORK"] = str(arguments["framework"])
            from . import reset as _reset
            _reset()
            sel = _selector()
        if fmt == "json":
            return {
                "benchmark": cat.benchmark,
                "version": cat.version,
                "framework": getattr(sel, "framework", None),
                "summary": sel.summary,
                "controls": [c.to_dict() for c in sel.selected],
            }
        return {"text": Reporter(color=False).list(cat, sel, format_=fmt).rstrip("\n")}
    if name == "scan":
        sel = _selector()
        return {"summary": sel.summary, "detectable": [c.id for c in sel.detectable]}
    if name == "plan":
        sel = _selector()
        return {"summary": sel.summary, "stacks": sel.stacks_for_apply,
                "controls": [c.id for c in sel.remediable]}
    if name in ("diff", "check_drift"):
        from .diff import diff as _diff
        from .drift import drift as _drift
        base = _load_scan(arguments.get("base"))
        cur = _load_scan(arguments.get("cur"))
        d = _diff(base, cur) if name == "diff" else _drift(base, cur)
        return d
    raise ValueError(f"unknown tool {name!r}")


def _load_scan(path: str) -> dict:
    from .diff import load_scan as _load
    data = _load(path)
    data["_path"] = str(path)
    return data


def _error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": JSON_RPC, "id": id_, "error": {"code": code, "message": message}}


def _respond(req: dict) -> dict:
    rid = req.get("id")
    method = req.get("method", "")
    if method == "tools/list":
        return {"jsonrpc": JSON_RPC, "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name not in {t["name"] for t in TOOLS}:
            return _error(rid, -32601, f"method not found: {name}")
        try:
            return {"jsonrpc": JSON_RPC, "id": rid, "result": _result(name, arguments)}
        except Exception as e:  # surface any tool failure as a JSON-RPC error
            return _error(rid, -32603, f"{type(e).__name__}: {e}")
    if method == "initialize":
        return {"jsonrpc": JSON_RPC, "id": rid,
                "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "ohbs-cloud", "version": "1.0.0"}}}
    if method == "notifications/initialized":
        return None
    return _error(rid, -32601, f"method not found: {method}")


def run_stdio(inp=None, outp=None) -> int:
    """Read JSON-RPC requests (one per line) from stdin, write responses out."""
    inp = inp or sys.stdin
    outp = outp or sys.stdout
    for line in inp:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            outp.write(json.dumps(_error(None, -32700, f"parse error: {e}"), ensure_ascii=False) + "\n")
            outp.flush()
            continue
        if not isinstance(req, dict):
            outp.write(json.dumps(_error(None, -32600, "invalid request"), ensure_ascii=False) + "\n")
            outp.flush()
            continue
        resp = _respond(req)
        if resp is not None:
            outp.write(json.dumps(resp, ensure_ascii=False) + "\n")
            outp.flush()
    return 0
