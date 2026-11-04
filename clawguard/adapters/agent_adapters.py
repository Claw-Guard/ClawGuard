"""Agent-specific protocol semantics without changing the policy backend."""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping


OPENCLAW = "openclaw"
CODEX = "codex"
CLAUDE = "claude"
SUPPORTED_AGENTS = {OPENCLAW, CODEX, CLAUDE}


_CODEX_TOOL_ALIASES = {
    "bash": "exec",
    "exec_command": "exec",
    "shell": "exec",
    "apply_patch": "apply_patch",
    "view_image": "read",
    "read": "read",
    "write": "write",
    "edit": "edit",
    "webfetch": "web_fetch",
    "web_fetch": "web_fetch",
    "websearch": "web_search",
    "web_search": "web_search",
}
_CODEX_NATIVE_TOOLS = {
    "apply_patch",
    "create_goal",
    "exec_command",
    "get_goal",
    "multi_agent_v1",
    "request_user_input",
    "update_goal",
    "view_image",
    "web_fetch",
    "web_search",
    "write_stdin",
}

_CLAUDE_TOOL_ALIASES = {
    "bash": "exec",
    "read": "read",
    "write": "write",
    "edit": "edit",
    "multiedit": "apply_patch",
    "webfetch": "web_fetch",
    "websearch": "web_search",
    "glob": "read",
    "grep": "read",
}
_CLAUDE_NATIVE_TOOLS = {
    "bash",
    "read",
    "write",
    "edit",
    "multiedit",
    "webfetch",
    "websearch",
    "glob",
    "grep",
    "task",
}

_OPENCLAW_BRIDGED_READ_ONLY_TOOLS = {
    "web_fetch": {
        "name": "web_fetch",
        "description": "Fetch a read-only web page.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "web_search": {
        "name": "web_search",
        "description": "Search the public web without side effects.",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
}


def normalize_agent(value: Any) -> str:
    normalized = str(value or OPENCLAW).strip().lower()
    if normalized not in SUPPORTED_AGENTS:
        choices = ", ".join(sorted(SUPPORTED_AGENTS))
        raise ValueError(f"agent must be one of: {choices}")
    return normalized


def canonical_tool_name(agent: str, name: Any) -> str:
    raw = str(name or "").strip()
    normalized = raw.casefold()
    for prefix in ("openclaw:core:", "openclaw_core_"):
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    if agent == CODEX:
        return _CODEX_TOOL_ALIASES.get(normalized, raw)
    if agent == CLAUDE:
        return _CLAUDE_TOOL_ALIASES.get(normalized, raw)
    return raw


def is_native_tool(agent: str, name: Any) -> bool:
    normalized = str(name or "").strip().casefold()
    if agent == CODEX:
        return normalized in _CODEX_NATIVE_TOOLS or normalized.startswith("mcp__")
    if agent == CLAUDE:
        return normalized in _CLAUDE_NATIVE_TOOLS or normalized.startswith("mcp__")
    return False


def native_tool_names(agent: str) -> tuple[str, ...]:
    if agent == CODEX:
        return tuple(sorted(_CODEX_NATIVE_TOOLS))
    if agent == CLAUDE:
        return tuple(sorted(_CLAUDE_NATIVE_TOOLS))
    return ()


def canonicalize_tool_registry(
    agent: str,
    registry: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Expose agent tools to Task Scope under their shared policy names."""

    if agent == OPENCLAW:
        result = {str(name): dict(value) for name, value in registry.items()}
        # OpenClaw can expose web primitives through its tool bridge without
        # repeating their schemas in the top-level registry. Treat those
        # read-only primitives as known policy tools while leaving the client
        # payload unchanged.
        bridge_names = {name.casefold() for name in result}
        if bridge_names & {"tool_search", "tool_call"}:
            existing = {name.casefold() for name in result}
            for name, schema in _OPENCLAW_BRIDGED_READ_ONLY_TOOLS.items():
                if name not in existing:
                    result[name] = dict(schema)
        return result
    result: Dict[str, Dict[str, Any]] = {}
    for name, schema in registry.items():
        canonical = canonical_tool_name(agent, name)
        entry = dict(schema)
        entry["agent_tool_name"] = str(name)
        result.setdefault(canonical, entry)
    return result


def filter_upstream_headers(
    agent: str,
    headers: Mapping[str, str],
) -> Dict[str, str]:
    """Remove client-specific headers that third-party providers may reject."""

    if agent != CODEX:
        return dict(headers)
    result: Dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.casefold()
        if lowered in {"authorization", "content-type"}:
            result[key] = value
    return result


def skill_roots(agent: str, home: str = "/home/node", cwd: str = "") -> tuple[str, ...]:
    """Return the documented local Skill discovery roots for an agent."""

    if agent == CODEX:
        roots = [
            f"{home}/.codex/skills",
            f"{home}/.agents/skills",
            "/etc/codex/skills",
        ]
        if cwd:
            roots.insert(0, f"{cwd}/.agents/skills")
        return tuple(roots)
    if agent == CLAUDE:
        roots = [f"{home}/.claude/skills"]
        if cwd:
            roots.insert(0, f"{cwd}/.claude/skills")
        return tuple(roots)
    roots = [f"{home}/.openclaw/workspace/skills", f"{home}/.openclaw/skills"]
    return tuple(roots)


def default_data_dir(agent: str, root: str = "~/.clawguard") -> str:
    """Return an isolated default state directory for an agent."""

    agent = normalize_agent(agent)
    return f"{root.rstrip('/')}/agents/{agent}"


_SKILL_BLOCK = re.compile(
    r"<skill>\s*<name>(?P<name>.*?)</name>\s*<path>(?P<path>.*?)</path>",
    re.DOTALL,
)


def extract_skill_contexts(payload: Mapping[str, Any]) -> list[Dict[str, str]]:
    """Extract Codex/Claude Skill blocks visible in a model request."""

    found: Dict[tuple[str, str], Dict[str, str]] = {}

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for child in value.values():
                visit(child)
            return
        if isinstance(value, list):
            for child in value:
                visit(child)
            return
        if not isinstance(value, str):
            return
        for match in _SKILL_BLOCK.finditer(value):
            name = match.group("name").strip()
            path = match.group("path").strip()
            if name and path:
                found[(name, path)] = {"name": name, "path": path}

    visit(payload.get("instructions"))
    visit(payload.get("input"))
    return list(found.values())
