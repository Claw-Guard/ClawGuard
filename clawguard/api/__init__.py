"""
Programmatic rule definition API for ClawGuard.

Provides a fluent builder interface for constructing custom security rules
at runtime, enabling dynamic rule generation in CI/CD pipelines and
security automation workflows.
"""

from clawguard.api.rules import RuleBuilder, CompiledRule

__all__ = ["RuleBuilder", "CompiledRule"]
