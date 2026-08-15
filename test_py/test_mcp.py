"""Tests for the MCP extension surface."""

from __future__ import annotations

import io
import json

from cis_cloud.mcp import _respond, run_stdio, TOOLS


def test_tools_list_lists_registry():
    resp = _respond({"id": 1, "method": "tools/list"})
    assert resp["result"]["tools"]
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"list", "scan", "plan", "diff", "check_drift"} <= names


def test_tools_call_list_returns_controls():
    resp = _respond({"id": 2, "method": "tools/call",
                     "params": {"name": "list", "arguments": {"format": "json"}}})
    assert resp["jsonrpc"] == "2.0" and resp["id"] == 2
    assert resp["result"]["controls"]
    assert resp["result"]["summary"]["selected"] > 0


def test_tools_call_scan_dry_run_returns_detectable():
    resp = _respond({"id": 3, "method": "tools/call",
                     "params": {"name": "scan", "arguments": {}}})
    assert "detectable" in resp["result"]


def test_tools_call_unknown_tool_errors():
    resp = _respond({"id": 4, "method": "tools/call",
                     "params": {"name": "nope", "arguments": {}}})
    assert resp["error"]["code"] == -32601


def test_run_stdio_round_trips():
    inp = io.StringIO(
        '{"id":1,"method":"tools/list"}\n'
        '{"id":2,"method":"tools/call","params":{"name":"list","arguments":{"format":"json"}}}\n'
    )
    out = io.StringIO()
    assert run_stdio(inp, out) == 0
    lines = [json.loads(l) for l in out.getvalue().strip().splitlines()]
    assert len(lines) == 2
    assert lines[0]["id"] == 1
    assert lines[1]["result"]["controls"]


def test_run_stdio_handles_malformed_line():
    inp = io.StringIO("not-json\n{\"id\":1,\"method\":\"tools/list\"}\n")
    out = io.StringIO()
    run_stdio(inp, out)
    lines = [json.loads(l) for l in out.getvalue().strip().splitlines()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["result"]
