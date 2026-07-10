"""Unit tests for the clawguard.api.rules module."""
import re
import pytest

from clawguard.api.rules import RuleBuilder, CompiledRule


class TestRuleBuilderBasics:
    """Tests for RuleBuilder basic construction and validation."""

    def test_create_with_valid_name(self):
        builder = RuleBuilder("test_rule")
        assert builder.name == "test_rule"
        assert builder._action == "deny"
        assert builder._reason == ""

    def test_create_with_empty_name_raises(self):
        with pytest.raises(ValueError, match="non-empty string"):
            RuleBuilder("")

    def test_create_with_non_string_name_raises(self):
        with pytest.raises(ValueError, match="non-empty string"):
            RuleBuilder(123)

    def test_build_without_patterns_raises(self):
        builder = RuleBuilder("empty_rule")
        with pytest.raises(ValueError, match="no patterns"):
            builder.build()


class TestRuleBuilderPatterns:
    """Tests for add_pattern method."""

    def test_add_valid_pattern(self):
        builder = RuleBuilder("test").add_pattern(r"exec\(.*\)")
        assert len(builder._patterns) == 1

    def test_add_invalid_pattern_raises(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            RuleBuilder("test").add_pattern(r"[unclosed")

    def test_add_non_string_pattern_raises(self):
        with pytest.raises(TypeError, match="must be a string"):
            RuleBuilder("test").add_pattern(123)

    def test_chained_patterns(self):
        rule = (
            RuleBuilder("multi")
            .add_pattern(r"a")
            .add_pattern(r"b")
            .add_pattern(r"c")
            .build()
        )
        # Combined pattern should match any of a, b, c
        assert rule.pattern.search("hello a world")
        assert rule.pattern.search("hello b world")
        assert rule.pattern.search("hello c world")
        assert not rule.pattern.search("hello d world")


class TestRuleBuilderBlocklist:
    """Tests for add_blocklist method."""

    def test_add_blocklist_items(self):
        rule = (
            RuleBuilder("dangerous")
            .add_blocklist(["rm -rf", "eval(", "exec("])
            .build()
        )
        assert rule.pattern.search("rm -rf /tmp")
        assert rule.pattern.search("eval(input())")
        assert rule.pattern.search("os.exec(cmd)")
        # Should not match similar but different strings
        assert not rule.pattern.search("rm -r /tmp")

    def test_add_blocklist_non_list_raises(self):
        with pytest.raises(TypeError, match="must be a list"):
            RuleBuilder("test").add_blocklist("not a list")

    def test_add_blocklist_non_string_item_raises(self):
        with pytest.raises(TypeError, match="must be strings"):
            RuleBuilder("test").add_blocklist(["valid", 123])

    def test_blocklist_items_are_regex_escaped(self):
        rule = (
            RuleBuilder("escape_test")
            .add_blocklist(["file.name"])
            .build()
        )
        # Period should be escaped, so it should NOT match "fileXname"
        assert rule.pattern.search("file.name")
        assert not rule.pattern.search("fileXname")


class TestRuleBuilderAllowlist:
    """Tests for add_allowlist method."""

    def test_add_allowlist_items(self):
        rule = (
            RuleBuilder("safe")
            .add_allowlist(["ls", "cat", "grep"])
            .with_action("allow")
            .build()
        )
        assert rule.action == "allow"
        assert rule.pattern.search("ls")
        assert rule.pattern.search("cat file.txt")


class TestRuleBuilderAction:
    """Tests for with_action method."""

    def test_valid_actions(self):
        for action in ("allow", "deny", "approve"):
            rule = (
                RuleBuilder(f"test_{action}")
                .add_pattern(r"x")
                .with_action(action)
                .build()
            )
            assert rule.action == action

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            RuleBuilder("test").add_pattern(r"x").with_action("block")

    def test_default_action_is_deny(self):
        rule = RuleBuilder("test").add_pattern(r"x").build()
        assert rule.action == "deny"


class TestRuleBuilderReasonAndType:
    """Tests for with_reason and with_rule_type methods."""

    def test_set_reason(self):
        rule = (
            RuleBuilder("test")
            .add_pattern(r"x")
            .with_reason("Custom reason here")
            .build()
        )
        assert rule.reason == "Custom reason here"

    def test_non_string_reason_raises(self):
        with pytest.raises(TypeError, match="must be a string"):
            RuleBuilder("test").add_pattern(r"x").with_reason(123)

    def test_set_rule_type(self):
        rule = (
            RuleBuilder("test")
            .add_pattern(r"x")
            .with_rule_type("mcp_injection")
            .build()
        )
        assert rule.rule_type == "mcp_injection"

    def test_non_string_rule_type_raises(self):
        with pytest.raises(TypeError, match="must be a string"):
            RuleBuilder("test").add_pattern(r"x").with_rule_type(123)


class TestCompiledRule:
    """Tests for CompiledRule dataclass."""

    def test_to_dict_contains_compiled_pattern(self):
        rule = (
            RuleBuilder("test")
            .add_pattern(r"exec")
            .with_action("deny")
            .with_reason("Test reason")
            .build()
        )
        result = rule.to_dict()
        # to_dict() now returns the compiled pattern for direct RuleEngine use
        assert hasattr(result["pattern"], "search")
        assert result["action"] == "deny"
        assert result["reason"] == "Test reason"
        # raw_pattern records the original combined pattern (wrapped in non-capturing group)
        assert "exec" in result["raw_pattern"]

    def test_to_yaml_dict_format(self):
        rule = (
            RuleBuilder("test")
            .add_pattern(r"exec")
            .with_action("deny")
            .with_reason("Test reason")
            .build()
        )
        result = rule.to_yaml_dict()
        assert "exec" in result["pattern"]
        assert result["action"] == "deny"
        assert result["reason"] == "Test reason"

    def test_to_dict_uses_default_reason(self):
        rule = RuleBuilder("my_rule").add_pattern(r"x").build()
        result = rule.to_dict()
        assert "my_rule" in result["reason"]


class TestBuildForSanitizer:
    """Tests for build_for_sanitizer method."""

    def test_sanitizer_format(self):
        rule = (
            RuleBuilder("api_key_detector")
            .add_pattern(r"sk-[A-Za-z0-9]{20,}")
            .build_for_sanitizer()
        )
        assert rule["name"] == "api_key_detector"
        assert "sk-[A-Za-z0-9]{20,}" in rule["pattern"]
        assert "[API_KEY_DETECTOR_REDACTED]" == rule["replacement"]


class TestIntegrationWithRuleEngine:
    """Tests for using rules with ClawGuard's RuleEngine."""

    def test_rule_engine_integration(self):
        from clawguard.rules import RuleEngine, ActionType

        rule = (
            RuleBuilder("mcp_injection")
            .add_blocklist(["specific_marker_xyz"])
            .with_action("deny")
            .with_reason("MCP tool injection attempt")
            .with_rule_type("mcp_injection")
            .build()
        )

        engine = RuleEngine()
        # Manually inject the rule into the blacklist
        engine.command_rules["blacklist"].append(rule.to_dict())

        # Use a command that won't trigger script analysis
        result = engine.check_command("specific_marker_xyz --test")
        assert result.matched is True
        assert result.action == ActionType.DENY
        assert "MCP tool injection" in result.reason
        # RuleEngine sets rule_type to "command_blacklist" when matching from blacklist
        assert result.rule_type == "command_blacklist"

    def test_sanitizer_integration(self):
        from clawguard.sanitizer import Sanitizer

        sanitizer = Sanitizer()
        rule = (
            RuleBuilder("internal_token")
            .add_pattern(r"internal_[A-Za-z0-9]{20,}")
            .with_action("deny")
            .build()
        )
        # Use the rule directly
        sanitizer.add_pattern(
            name=rule.name,
            pattern=rule.pattern.pattern,
            replacement=rule.replacement,
        )

        result = sanitizer.sanitize("Token is internal_abc123def456ghi789jkl012")
        assert "[INTERNAL_TOKEN_REDACTED]" in result
