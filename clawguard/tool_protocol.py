"""Canonical tool-call protocol shared by parsing and policy evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple


@dataclass(frozen=True)
class CanonicalToolCall:
    """One normalized function call, regardless of provider wire format."""

    id: str
    name: str
    arguments: str = ""
    wrapper: str = ""
    envelope: Optional[Mapping[str, str]] = None
    protocol: str = "chat_completions"

    @classmethod
    def coerce(cls, value: Any) -> "CanonicalToolCall":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("tool call must be a mapping or CanonicalToolCall")
        raw_arguments = value.get("arguments")
        if raw_arguments is None:
            arguments = ""
        elif isinstance(raw_arguments, str):
            arguments = raw_arguments
        else:
            arguments = json.dumps(
                raw_arguments,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        return cls(
            id=str(value.get("id") or ""),
            name=str(value.get("name") or "").strip(),
            arguments=arguments,
            wrapper=str(value.get("wrapper") or ""),
            envelope=(
                dict(value["envelope"])
                if isinstance(value.get("envelope"), Mapping)
                else None
            ),
            protocol=str(value.get("protocol") or "chat_completions"),
        )

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "protocol": self.protocol,
        }
        if self.wrapper:
            result["wrapper"] = self.wrapper
        if self.envelope is not None:
            result["envelope"] = dict(self.envelope)
        return result

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self.to_dict()


@dataclass(frozen=True)
class ToolCallFacts:
    """Provider-independent facts extracted by one tool adapter."""

    tool_name: str
    registry_name: str
    capabilities: Tuple[str, ...] = ()
    authorization_capabilities: Tuple[str, ...] = ()
    adapter_name: str = ""
    commands: Tuple[str, ...] = ()
    file_targets: Tuple[Tuple[str, str], ...] = ()
    urls: Tuple[str, ...] = ()
    cwd: Optional[str] = None
    process_action: str = ""
    opaque: bool = False
    network_missing_url: bool = False
    invalid_reason: Optional[str] = None

    def has_targets(self) -> bool:
        return bool(
            self.commands
            or self.file_targets
            or self.urls
            or self.process_action
        )


@dataclass(frozen=True)
class PolicyDecision:
    """Stable outcome of one unified policy evaluation."""

    action: str
    rule_type: str
    reason: str
    pattern: Optional[str] = None
    tool_name: str = ""
    capability: str = ""
    target: str = ""
    facts: Optional[ToolCallFacts] = field(default=None, compare=False)


def arguments_object(call: CanonicalToolCall) -> Optional[Dict[str, Any]]:
    """Return parsed object arguments or None for invalid/non-object JSON."""
    if call.arguments == "":
        return {}
    try:
        parsed = json.loads(call.arguments)
    except (TypeError, ValueError):
        return None
    return dict(parsed) if isinstance(parsed, Mapping) else None
