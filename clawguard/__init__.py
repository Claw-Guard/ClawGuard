"""
ClawGuard - AI Agent Security Framework
Python implementation for securing AI agent operations.
"""

__version__ = "1.0.0"
__author__ = "ClawGuard Contributors"

from clawguard.sanitizer import Sanitizer
from clawguard.rules import RuleEngine
from clawguard.audit import AuditLogger
from clawguard.approval import ApprovalQueue
from clawguard.panic import PanicManager
from clawguard.skill_check import SkillChecker
from clawguard.script_analyzer import ScriptAnalyzer, ScriptAnalysisResult, ScriptRisk

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
]
