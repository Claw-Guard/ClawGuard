"""
RuleBuilder: Fluent builder for programmatic security rules.

Allows defining custom detection rules without YAML config files,
useful for dynamic rule generation in CI/CD pipelines and security
automation.
"""

import re
from typing import List, Pattern
from dataclasses import dataclass


@dataclass
class CompiledRule:
    """A compiled rule ready for RuleEngine consumption."""
    name: str
    pattern: Pattern
    replacement: str
    action: str = "deny"
    reason: str = ""
    rule_type: str = "custom"

    def to_dict(self) -> dict:
        """Convert to RuleEngine._load_rules() format.

        Note: This returns a dict with the compiled pattern, suitable for
        direct injection into RuleEngine.command_rules["blacklist"]/etc.
        For YAML serialization, use to_yaml_dict() instead.
        """
        return {
            "pattern": self.pattern,
            "action": self.action,
            "reason": self.reason or f"Custom rule: {self.name}",
            "raw_pattern": self.pattern.pattern,
        }

    def to_yaml_dict(self) -> dict:
        """Convert to YAML-serializable format (string pattern)."""
        return {
            "pattern": self.pattern.pattern,
            "action": self.action,
            "reason": self.reason or f"Custom rule: {self.name}",
        }


class RuleBuilder:
    """
    Fluent builder for programmatic rule construction.

    Supports pattern-based, blocklist, and allowlist rules for use
    with ClawGuard's RuleEngine.

    Example:
        rule = (RuleBuilder("mcp_tool_injection")
                .add_pattern(r"exec\\(.*\\)")
                .add_blocklist(["rm -rf", "eval("])
                .with_action("deny")
                .with_reason("Tool injection pattern detected")
                .build())

        safe_rule = (RuleBuilder("safe_commands")
                     .add_pattern(r"^(ls|cat|grep)$")
                     .with_action("allow")
                     .with_reason("Standard read-only commands")
                     .build())
    """

    def __init__(self, name: str):
        if not name or not isinstance(name, str):
            raise ValueError("Rule name must be a non-empty string")
        self.name = name
        self._patterns: List[str] = []
        self._action: str = "deny"
        self._reason: str = ""
        self._rule_type: str = "custom"

    def add_pattern(self, pattern: str) -> "RuleBuilder":
        """
        Add a regex pattern that triggers the rule.

        Args:
            pattern: Regular expression string

        Returns:
            self for chaining
        """
        if not isinstance(pattern, str):
            raise TypeError(f"Pattern must be a string, got {type(pattern).__name__}")
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        self._patterns.append(pattern)
        return self

    def add_blocklist(self, items: List[str]) -> "RuleBuilder":
        """
        Add exact-match blocklist items (regex-escaped).

        Args:
            items: List of literal strings to block

        Returns:
            self for chaining
        """
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"Blocklist must be a list, got {type(items).__name__}")
        for item in items:
            if not isinstance(item, str):
                raise TypeError(f"Items must be strings, got {type(item).__name__}")
            self._patterns.append(re.escape(item))
        return self

    def add_allowlist(self, items: List[str]) -> "RuleBuilder":
        """
        Add exact-match allowlist items (regex-escaped).

        Note: Combine with with_action("allow").

        Args:
            items: List of literal strings to allow

        Returns:
            self for chaining
        """
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"Allowlist must be a list, got {type(items).__name__}")
        for item in items:
            if not isinstance(item, str):
                raise TypeError(f"Items must be strings, got {type(item).__name__}")
            self._patterns.append(re.escape(item))
        return self

    def with_action(self, action: str) -> "RuleBuilder":
        """
        Set the action triggered by this rule.

        Args:
            action: One of "allow", "deny", "approve"

        Returns:
            self for chaining
        """
        valid_actions = ("allow", "deny", "approve")
        if action not in valid_actions:
            raise ValueError(
                f"Invalid action '{action}'. Must be one of {valid_actions}"
            )
        self._action = action
        return self

    def with_reason(self, reason: str) -> "RuleBuilder":
        """
        Set a human-readable reason for the rule match.

        Args:
            reason: Description shown when rule triggers

        Returns:
            self for chaining
        """
        if not isinstance(reason, str):
            raise TypeError(f"Reason must be a string, got {type(reason).__name__}")
        self._reason = reason
        return self

    def with_rule_type(self, rule_type: str) -> "RuleBuilder":
        """
        Set a custom rule_type for categorization.

        Args:
            rule_type: Category name (e.g., "mcp_injection", "tool_call")

        Returns:
            self for chaining
        """
        if not isinstance(rule_type, str):
            raise TypeError(f"rule_type must be a string, got {type(rule_type).__name__}")
        self._rule_type = rule_type
        return self

    def build(self) -> CompiledRule:
        """
        Build the compiled rule.

        Returns:
            CompiledRule ready for RuleEngine

        Raises:
            ValueError: If no patterns or items have been added
        """
        if not self._patterns:
            raise ValueError(
                f"Rule '{self.name}' has no patterns. "
                "Call add_pattern(), add_blocklist(), or add_allowlist() first."
            )

        combined = "|".join(f"(?:{p})" for p in self._patterns)
        try:
            compiled_pattern = re.compile(combined)
        except re.error as e:
            raise ValueError(f"Failed to compile combined pattern: {e}")

        return CompiledRule(
            name=self.name,
            pattern=compiled_pattern,
            replacement=f"[{self.name.upper()}_REDACTED]",
            action=self._action,
            reason=self._reason or f"Custom rule '{self.name}' matched",
            rule_type=self._rule_type,
        )

    def build_for_sanitizer(self) -> dict:
        """
        Build the rule as a sanitizer pattern dict.

        Returns:
            Dict suitable for Sanitizer.add_pattern()
        """
        rule = self.build()
        return {
            "name": rule.name,
            "pattern": rule.pattern.pattern,
            "replacement": rule.replacement,
        }
