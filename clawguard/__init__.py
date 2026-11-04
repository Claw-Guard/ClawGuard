"""
ClawGuard - AI Agent Security Framework
Python implementation for securing AI agent operations.
"""

__version__ = "2026.11.3"
__author__ = "ClawGuard Contributors"

from clawguard.sanitizer import Sanitizer
from clawguard.rules import RuleEngine
from clawguard.audit import AuditLogger
from clawguard.approval import ApprovalQueue
from clawguard.panic import PanicManager
from clawguard.skill_check import SkillChecker
from clawguard.script_analyzer import ScriptAnalyzer, ScriptAnalysisResult, ScriptRisk
from clawguard.tool_protocol import CanonicalToolCall, PolicyDecision, ToolCallFacts
from clawguard.skill_inspector import (
    SkillBundle,
    SkillInspector,
    SkillReviewStore,
    SkillVerdict,
)

__all__ = [
    "Sanitizer",
    "RuleEngine",
    "AuditLogger",
    "ApprovalQueue",
    "PanicManager",
    "SkillChecker",
    "ScriptAnalyzer",
    "ScriptAnalysisResult",
    "ScriptRisk",
    "CanonicalToolCall",
    "ToolCallFacts",
    "PolicyDecision",
    "SkillBundle",
    "SkillInspector",
    "SkillReviewStore",
    "SkillVerdict",
]
