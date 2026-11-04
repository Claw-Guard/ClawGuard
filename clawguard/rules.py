"""
Rule Engine Module (Rule Engine Module)
Responsible for command, file, and network rule matching and decision
"""

import re
import os
import shlex
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import yaml
import fnmatch
from urllib.parse import urlparse

try:
    from .normalizer import CommandNormalizer
except ImportError:
    CommandNormalizer = None

try:
    from .script_analyzer import ScriptAnalyzer, ScriptRisk
except ImportError:
    ScriptAnalyzer = None
    ScriptRisk = None


# Native tool names that denote the same capability.  A task scope may
# disable a capability under any of its spellings, so membership is checked
# group-wise rather than by exact name alone.
_TOOL_ALIAS_GROUPS = (
    {
        "exec", "execute", "execute_command", "shell", "run_command",
        "command", "bash", "sh",
    },
    {"process"},
    {
        "read", "read_file", "file_read", "read_workspace", "cat", "head",
        "tail", "grep", "list_directory", "list_dir", "directory_list",
    },
    {
        "write", "write_file", "file_write", "write_workspace", "edit",
        "edit_file", "apply_patch",
    },
    {
        "http", "http_request", "fetch", "web_fetch", "web_search", "browser",
        "browser_open", "browser_navigate",
    },
)


def _path_overlap_key(entry: str) -> str:
    """Reduce one path entry to a comparable key.

    ``~`` is expanded and trailing glob segments are dropped so ``~/work``,
    ``~/work/`` and ``~/work/**`` all collapse to the same key.
    """
    text = os.path.expanduser(str(entry or "").strip()).replace("\\", "/")
    while text.endswith("/"):
        text = text[:-1]
    while text.endswith("*"):
        text = text[:-1].rstrip("/")
    return os.path.normcase(text)


def _paths_overlap(key_a: str, key_b: str) -> bool:
    """Return True when two path keys are the same path or nested in each other."""
    if not key_a or not key_b:
        return False
    if key_a == key_b:
        return True
    return key_a.startswith(key_b + os.sep) or key_b.startswith(key_a + os.sep)


def _domain_overlap_key(entry: str) -> str:
    """Reduce one domain entry to a comparable host (wildcards folded away)."""
    text = str(entry or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    return text


def _domains_overlap(key_a: str, key_b: str) -> bool:
    """Return True for the same host or a parent/child host relation."""
    if not key_a or not key_b:
        return False
    if key_a == key_b:
        return True
    return key_a.endswith("." + key_b) or key_b.endswith("." + key_a)


def find_policy_overlaps(config: Optional[Dict[str, Any]] = None) -> List[str]:
    """Report allow/deny entries that obviously target the same thing.

    An allow entry that is equal to, inside, or a parent of a deny entry makes
    the policy self-contradictory: the deny entry always wins, so the allow
    entry can never take effect.  Only obvious cases are reported — globs are
    reduced to their literal prefix and domain checks cover exact hosts plus
    the parent/child relation, so this stays a cheap config sanity check
    rather than a full pattern algebra.
    """
    config = config or {}
    file_rules = config.get("file_rules") or {}
    net_rules = config.get("network_rules") or {}

    overlaps: List[str] = []

    denied_paths = [str(item) for item in (file_rules.get("denied_paths") or [])]
    for allowed in [str(item) for item in (file_rules.get("allowed_paths") or [])]:
        for denied in denied_paths:
            if _paths_overlap(_path_overlap_key(allowed), _path_overlap_key(denied)):
                overlaps.append(
                    f"file_rules.allowed_paths '{allowed}' overlaps "
                    f"file_rules.denied_paths '{denied}'"
                )

    denied_domains = [str(item) for item in (net_rules.get("denied_domains") or [])]
    for allowed in [str(item) for item in (net_rules.get("allowed_domains") or [])]:
        for denied in denied_domains:
            if _domains_overlap(_domain_overlap_key(allowed), _domain_overlap_key(denied)):
                overlaps.append(
                    f"network_rules.allowed_domains '{allowed}' overlaps "
                    f"network_rules.denied_domains '{denied}'"
                )

    return overlaps


class ActionType(Enum):
    """Operation Type"""
    ALLOW = "allow"
    DENY = "deny"
    APPROVE = "approve"  # Supervised


@dataclass
class RuleMatch:
    """Rule Match Result"""
    matched: bool
    action: ActionType
    reason: str
    pattern: Optional[str] = None
    rule_type: str = "unknown"
    scope_checked: bool = False


class RuleEngine:
    """
    Rule Engine
    
    Handle three types of rules:
    1. Command Rules (command_rules) - blacklist/whitelist/supervised
    2. File Rules (file_rules) - path access control
    3. Network Rules (network_rules) - domain whitelist
    """
    
    def __init__(self, rules_config: Optional[Dict[str, Any]] = None):
        """
        Initialize Rule Engine
        
        Args:
            rules_config: （From rules.yaml Load）
        """
        self.command_rules = {
            "blacklist": [],
            "whitelist": [],
            "supervised": [],
        }
        self.file_rules = {
            "allowed_paths": [],
            "denied_paths": [],
            "sensitive_patterns": [],
        }
        self.network_rules = {
            "allowed_domains": [],
            "denied_domains": [],
            "default_action": ActionType.APPROVE,
        }
        
        # Initialize command normalizer
        self.normalizer = CommandNormalizer() if CommandNormalizer else None
        # Initialize script analyzer
        self.script_analyzer = ScriptAnalyzer(rule_engine=self) if ScriptAnalyzer else None
        
        # Task scope state (per-session injected rules)
        self.task_scope_active = False
        self.task_scope_locked = False  # When True, set_task_scope calls are rejected
        self.task_scope_rules = {
            "file_traverse": [],
            "directory_list": [],
            "file_read": [],
            "file_write": [],
            "commands": [],
            "network": [],
            "allowed_capabilities": [],
            "capability_adapters": False,
            "disabled_tools": [],
            "explicit_disabled_tools": [],
            "inferred_disabled_tools": [],
            # ``None`` preserves the legacy category-based behavior.  The LLM
            # gateway supplies a list (including an empty list) to enforce a
            # strict per-session model-tool allowlist.
            "allowed_tools": None,
        }
        self.command_working_dir = os.path.realpath(
            os.environ.get("OPENCLAW_WORKSPACE_DIR") or os.getcwd()
        )
        
        # Allow/deny entries that target the same thing; reported at startup
        # because the deny entry always wins and the allow entry is dead.
        self.policy_overlaps: List[str] = []

        if rules_config:
            self._load_rules(rules_config)
            self.policy_overlaps = find_policy_overlaps(rules_config)
    
    def _load_rules(self, config: Dict[str, Any]):
        """Load rules"""
        # Load Command Rules
        cmd_rules = config.get("command_rules", {})
        for category in ["blacklist", "whitelist", "supervised"]:
            for rule in cmd_rules.get(category, []):
                self.command_rules[category].append({
                    "pattern": re.compile(rule["pattern"]),
                    "action": ActionType(rule["action"]),
                    "reason": rule.get("reason", ""),
                    "raw_pattern": rule["pattern"],
                })
        
        # Load File Rules
        file_rules = config.get("file_rules", {})
        self.file_rules["allowed_paths"] = self._expand_paths(
            file_rules.get("allowed_paths", [])
        )
        self.file_rules["denied_paths"] = self._expand_paths(
            file_rules.get("denied_paths", [])
        )
        self.file_rules["sensitive_patterns"] = file_rules.get("sensitive_patterns", [])
        
        # Load Network Rules
        net_rules = config.get("network_rules", {})
        self.network_rules["allowed_domains"] = net_rules.get("allowed_domains", [])
        self.network_rules["denied_domains"] = net_rules.get("denied_domains", [])
        default = net_rules.get("default_action", "approve")
        self.network_rules["default_action"] = ActionType(default)
    
    def _expand_paths(self, paths: List[str]) -> List[str]:
        """Expand ~ to user directory in paths"""
        return [os.path.expanduser(p) for p in paths]

    def _derive_task_scope_traversals(
        self,
        file_paths: List[str],
        commands: List[str],
    ) -> List[str]:
        """Derive directory traversal grants from target paths and cd commands."""
        candidates: List[str] = []
        for raw_path in file_paths:
            text = self._expand_shell_home(str(raw_path or "").strip())
            if not text or self._is_url_like(text):
                continue
            wildcard_index = min(
                (
                    index
                    for marker in ("*", "?", "[")
                    if (index := text.find(marker)) >= 0
                ),
                default=-1,
            )
            if wildcard_index >= 0:
                text = text[:wildcard_index].rstrip("/") or os.sep
            candidates.append(text)
            candidates.append(os.path.dirname(text))

        for command in commands:
            try:
                tokens = self._shell_tokens(str(command))
            except ValueError:
                continue
            segment: List[str] = []
            segments: List[List[str]] = []
            for token in tokens + [";"]:
                if token in {";", "&&", "||", "|", "&"}:
                    if segment:
                        segments.append(segment)
                        segment = []
                else:
                    segment.append(token)
            for item in segments:
                if len(item) >= 2 and os.path.basename(item[0]).casefold() == "cd":
                    target = self._resolve_command_path(item[1], None)
                    if target:
                        candidates.append(target)

        traversals: List[str] = []
        for raw_path in candidates:
            path = self._resolve_command_path(raw_path, self.command_working_dir)
            if not path:
                continue
            while True:
                if path not in traversals:
                    traversals.append(path)
                parent = os.path.dirname(path)
                if parent == path:
                    break
                path = parent
        return traversals

    @staticmethod
    def _derive_task_scope_capabilities(
        allowed_tools: Optional[List[str]],
        file_read: List[str],
        file_write: List[str],
        network: List[str],
        commands: List[str],
    ) -> List[str]:
        capabilities = set()
        for raw_tool in allowed_tools or []:
            tool = str(raw_tool or "").strip().casefold()
            if tool in _TOOL_ALIAS_GROUPS[2]:
                capabilities.add("file_read")
            elif tool in _TOOL_ALIAS_GROUPS[3]:
                capabilities.add("file_write")
            elif tool in _TOOL_ALIAS_GROUPS[4]:
                capabilities.add("network_read")
            elif tool in _TOOL_ALIAS_GROUPS[0]:
                capabilities.add("command")
            elif tool in _TOOL_ALIAS_GROUPS[1]:
                capabilities.add("process")
        if file_read:
            capabilities.add("file_read")
        if file_write:
            capabilities.add("file_write")
        if network:
            capabilities.add("network_read")
        if commands:
            capabilities.add("command")
        return sorted(capabilities)

    def scope_allows_capabilities(self, capabilities: List[str]) -> bool:
        """Return whether active capability-adapted tools are authorized."""
        if not self.task_scope_active:
            return True
        required = {str(item) for item in capabilities if item}
        if not required:
            return False
        allowed = {
            str(item)
            for item in self.task_scope_rules.get("allowed_capabilities", [])
        }
        return required.issubset(allowed)
    
    # ================================
    # Command Rules
    # ================================

    @staticmethod
    def _combine_base_and_scope(
        base: RuleMatch,
        scope: Optional[RuleMatch],
        *,
        operation: str,
    ) -> RuleMatch:
        """Combine base policy and task scope with strict intersection semantics.

        An explicit base denial is final.  When scope is active, a positive
        base allow is necessary but not sufficient: every target must also be
        covered by the scope.  A base approval remains approval even when the
        scope allows the operation.
        """
        if base.action == ActionType.DENY:
            return base
        if scope is None:
            return base
        if base.matched and base.action == ActionType.APPROVE:
            # Base approval is authoritative.  Task scope may narrow direct
            # allows, but it must not turn a human-review decision into the
            # recoverable, model-visible task-scope denial path.
            return base
        if scope.action == ActionType.DENY:
            return RuleMatch(
                True,
                ActionType.DENY,
                f"Task scope denied {operation}: {scope.reason}",
                scope.pattern,
                "task_scope_restriction",
            )
        if scope.action == ActionType.APPROVE:
            return scope
        if base.matched and base.action == ActionType.ALLOW:
            return RuleMatch(
                True,
                ActionType.ALLOW,
                f"Base rules and task scope allow {operation}",
                base.pattern,
                base.rule_type,
            )
        return scope
    
    def check_command(
        self,
        command: str,
        cwd: Optional[str] = None,
        *,
        ignore_task_scope_commands: bool = False,
    ) -> RuleMatch:
        """Require the command to satisfy both base policy and task scope."""
        base = self._base_command_match(
            command,
            cwd=cwd,
            ignore_task_scope_commands=ignore_task_scope_commands,
        )
        if base.scope_checked or ignore_task_scope_commands:
            return base
        scope_result = self._check_task_scope_command(command)
        return self._combine_base_and_scope(
            base,
            scope_result,
            operation="command",
        )

    def _base_command_match(
        self,
        command: str,
        *,
        cwd: Optional[str] = None,
        allow_compound: bool = True,
        ignore_task_scope_commands: bool = False,
    ) -> RuleMatch:
        """
        Check command
        
        Args:
            command: Command
            
        Returns:
            RuleMatch: Match result
        """
        # An explicit deny match is final and cannot be hidden inside a shell
        # sequence, a pipeline, or an interpreter invocation.
        blacklist_result = self._match_command_blacklist(command)
        if blacklist_result is not None:
            return blacklist_result

        if allow_compound:
            sequence_result = self._check_shell_sequence(
                command,
                cwd=cwd,
                ignore_task_scope_commands=ignore_task_scope_commands,
            )
            if sequence_result is not None:
                return sequence_result

        # ── Script analysis (runs BEFORE whitelist) ──────────────────────────
        # If the command is: python foo.py / node foo.js / bash foo.sh etc.,
        # inspect the script content before trusting the command string.
        if self.script_analyzer:
            script_result = self._check_script_in_command(command)
            if script_result is not None:
                return script_result

            # If the command uses -c/-e with inline code, analyse that string.
            inline_result = self._check_inline_script(command)
            if inline_result is not None:
                return inline_result

        # ── File path check (runs BEFORE whitelist) ──────────────────────────
        # If the command reads a file, cross-check the path against file_rules.
        # This catches e.g. `cat /etc/passwd` even though `cat` is whitelisted.
        file_result = self._check_file_in_command(command, cwd=cwd)
        if file_result is not None:
            return file_result

        network_result = self._check_network_in_command(command)
        if network_result is not None:
            return network_result

        sensitive_result = self._check_sensitive_shell_usage(command)
        if sensitive_result is not None:
            return sensitive_result

        # Normalize command first to detect obfuscation
        normalized_cmd = command
        obfuscation_warnings = []
        
        if self.normalizer:
            normalized_cmd, obfuscation_warnings = self.normalizer.normalize(command)
            
            # If high obfuscation detected, flag for approval
            obfuscation_level = self.normalizer.detect_obfuscation_level(command)
            if obfuscation_level == 'high':
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=f"🚨 High obfuscation detected: {', '.join(obfuscation_warnings)}",
                    pattern="obfuscation_detection",
                    rule_type="command_obfuscation",
                )
            elif obfuscation_level == 'medium':
                return RuleMatch(
                    matched=True,
                    action=ActionType.APPROVE,
                    reason=f"⚠️ Medium obfuscation detected: {', '.join(obfuscation_warnings)}",
                    pattern="obfuscation_detection",
                    rule_type="command_obfuscation",
                )
        
        # Check both original and normalized command
        commands_to_check = [command]
        if normalized_cmd != command:
            commands_to_check.append(normalized_cmd)
        
        for cmd_to_check in commands_to_check:
            # 1. Check blacklist first (highest priority — task scope cannot override)
            for rule in self.command_rules["blacklist"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.DENY,
                        reason=rule["reason"],
                        pattern=rule["raw_pattern"],
                        rule_type="command_blacklist",
                    )
        
        # Task scope is applied by the public wrapper after this base chain.
        
        for cmd_to_check in commands_to_check:
            # 3. Check whitelist (allow)
            for rule in self.command_rules["whitelist"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.ALLOW,
                        reason="Command in whitelist",
                        pattern=rule["raw_pattern"],
                        rule_type="command_whitelist",
                    )
            
            # 4. Check supervised list
            for rule in self.command_rules["supervised"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.APPROVE,
                        reason=rule["reason"],
                        pattern=rule["raw_pattern"],
                        rule_type="command_supervised",
                    )
        
        # Unknown commands never execute silently.  In supervised mode this
        # produces a human approval; strict mode converts it to a denial.
        return RuleMatch(
            matched=False,
            action=ActionType.APPROVE,
            reason="Command is not explicitly recognized; approval required",
            rule_type="command_default",
        )
    
    # ================================
    # Script Analysis (helper)
    # ================================

    @staticmethod
    def _merge_command_matches(matches) -> Optional[RuleMatch]:
        """Return the strongest command decision, if any."""
        priority = {
            ActionType.ALLOW: 0,
            ActionType.APPROVE: 1,
            ActionType.DENY: 2,
        }
        strongest: Optional[RuleMatch] = None
        for match in matches:
            if match is None:
                continue
            if strongest is None or priority[match.action] > priority[strongest.action]:
                strongest = match
        return strongest

    def _match_command_blacklist(self, command: str) -> Optional[RuleMatch]:
        for rule in self.command_rules["blacklist"]:
            if rule["pattern"].search(command):
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=rule["reason"],
                    pattern=rule["raw_pattern"],
                    rule_type="command_blacklist",
                )
        return None

    @staticmethod
    def _shell_tokens(command: str) -> List[str]:
        # ``shlex(posix=True)`` treats backslashes as escape characters, which
        # turns ``C:\\vault\\secret.txt`` into ``C:vaultsecret.txt``.  Normalize
        # drive-letter paths for analysis only so quoted/unquoted Windows paths
        # still reach file_rules.  The original command is never rewritten.
        windows_path = re.compile(
            r"(?<![A-Za-z0-9_])([A-Za-z]):\\([^\s'\"<>|;&]*)"
        )
        token_source = windows_path.sub(
            lambda match: f"{match.group(1)}:/{match.group(2).replace(chr(92), '/')}",
            command,
        )
        lexer = shlex.shlex(
            token_source,
            posix=True,
            punctuation_chars=";&|<>()",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)

    def _resolve_command_path(self, path: str, cwd: Optional[str]) -> Optional[str]:
        path = self._expand_shell_home(path.strip().strip("'\""))
        if not path or self._is_url_like(path):
            return None
        if os.path.isabs(path) or path.startswith("~"):
            return os.path.realpath(os.path.expanduser(path))
        base = cwd or self.command_working_dir
        if not base:
            return None
        return os.path.realpath(os.path.join(base, path))

    def _check_shell_sequence(
        self,
        command: str,
        *,
        cwd: Optional[str],
        ignore_task_scope_commands: bool = False,
    ) -> Optional[RuleMatch]:
        """Analyze sequencing, pipelines, substitutions and redirections.

        The analyzer is deliberately conservative: syntax it cannot model
        faithfully is approval-gated instead of being passed to a shell.
        Every concrete command segment is still checked against the ordinary
        blacklist, file, network and command rules.
        """
        if "\n" in command or "\r" in command:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Multi-line shell commands require approval",
                rule_type="command_multiline",
            )
        try:
            tokens = self._shell_tokens(command)
        except ValueError as exc:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                f"Unparseable shell syntax requires approval: {exc}",
                rule_type="command_shell_parse",
            )

        control = {";", "&&", "||", "|", "&"}
        redirections = {">", ">>", ">|", "&>", "&>>", "<", "<<", "<<<", ">&"}
        has_shell_syntax = any(
            token in control
            or token in redirections
            or token in {"(", ")"}
            or token == "$"
            or token.startswith("`")
            or "$" in token
            for token in tokens
        )
        if not has_shell_syntax:
            return None
        if any(
            token.startswith("`") or "$" in token or token == "$"
            for token in tokens
        ):
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Shell expansion or command substitution requires approval",
                rule_type="command_shell_expansion",
            )
        if any(token in {"(", ")"} for token in tokens):
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Shell subshell/group syntax requires approval",
                rule_type="command_shell_group",
            )

        segments: List[List[str]] = []
        current: List[str] = []
        operators: List[str] = []
        for token in tokens:
            if token in control:
                if current:
                    segments.append(current)
                    current = []
                operators.append(token)
            else:
                current.append(token)
        if current:
            segments.append(current)
        if not segments:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Shell command has no executable segment",
                rule_type="command_shell_empty",
            )

        checks: List[RuleMatch] = []
        current_cwd = os.path.realpath(cwd or self.command_working_dir)
        background = "&" in operators
        for segment in segments:
            clean_tokens: List[str] = []
            index = 0
            while index < len(segment):
                token = segment[index]
                if (
                    token.isdigit()
                    and index + 1 < len(segment)
                    and segment[index + 1] in redirections
                ):
                    index += 1
                    continue
                if token in redirections:
                    if index + 1 >= len(segment):
                        checks.append(
                            RuleMatch(
                                True,
                                ActionType.APPROVE,
                                "Shell redirection has no inspectable target",
                                rule_type="command_redirection",
                            )
                        )
                        index += 1
                        continue
                    target = segment[index + 1]
                    if token in {"<<", "<<<"}:
                        checks.append(
                            RuleMatch(
                                True,
                                ActionType.APPROVE,
                                "Here-document/here-string requires approval",
                                rule_type="command_heredoc",
                            )
                        )
                    elif token == ">&" and (
                        target.isdigit() or target.startswith("-")
                    ):
                        pass
                    elif target in {"/dev/null"}:
                        pass
                    else:
                        resolved = self._resolve_command_path(target, current_cwd)
                        if resolved is None:
                            checks.append(
                                RuleMatch(
                                    True,
                                    ActionType.APPROVE,
                                    f"Unresolved redirection target: {target}",
                                    rule_type="command_redirection",
                                )
                            )
                        else:
                            operation = "read" if token in {"<"} else "write"
                            checks.append(
                                self.check_file_path(resolved, operation)
                            )
                    index += 2
                    continue
                clean_tokens.append(token)
                index += 1

            if not clean_tokens:
                continue

            command_name = os.path.basename(clean_tokens[0]).casefold()
            if command_name == "cd":
                if len(clean_tokens) != 2 or clean_tokens[1] == "-":
                    checks.append(
                        RuleMatch(
                            True,
                            ActionType.APPROVE,
                            "Non-literal directory change requires approval",
                            rule_type="command_cd",
                        )
                    )
                    continue
                target_path = self._resolve_command_path(
                    clean_tokens[1],
                    current_cwd,
                )
                if target_path is None:
                    checks.append(
                        RuleMatch(
                            True,
                            ActionType.APPROVE,
                            f"Unresolved directory change: {clean_tokens[1]}",
                            rule_type="command_cd",
                        )
                    )
                    continue
                directory_match = self.check_file_path(target_path, "traverse")
                checks.append(directory_match)
                # Even when entering a directory itself requires approval,
                # subsequent relative paths must be analyzed as if the shell
                # had performed the cd. Otherwise approving the whole compound
                # command could expose a denied child path.
                current_cwd = target_path
                continue

            segment_command = shlex.join(clean_tokens)
            segment_base = self._base_command_match(
                segment_command,
                cwd=current_cwd,
                allow_compound=False,
                ignore_task_scope_commands=ignore_task_scope_commands,
            )
            checks.append(
                self._combine_base_and_scope(
                    segment_base,
                    (
                        None
                        if ignore_task_scope_commands
                        else self._check_task_scope_command(
                            segment_command,
                            shell_analyzed=True,
                        )
                    ),
                    operation="command segment",
                )
            )

        strongest = self._merge_command_matches(checks)
        if strongest is not None and strongest.action == ActionType.DENY:
            return RuleMatch(
                True,
                ActionType.DENY,
                strongest.reason,
                strongest.pattern,
                strongest.rule_type,
                True,
            )
        if background:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Background shell execution requires approval",
                pattern=strongest.pattern if strongest else None,
                rule_type="command_background",
                scope_checked=True,
            )
        if strongest is not None:
            return RuleMatch(
                True,
                strongest.action,
                strongest.reason,
                strongest.pattern,
                strongest.rule_type,
                True,
            )
        return RuleMatch(
            True,
            ActionType.APPROVE,
            "Unrecognized shell construction requires approval",
            rule_type="command_shell_unrecognized",
        )

    # Commands that read, copy out or archive file content — their path
    # arguments are cross-checked against file_rules before the command
    # blacklist/whitelist runs, so `cat`, `cp`, `base64`, `dd`, `tar` and the
    # Windows/PowerShell equivalents cannot smuggle a denied path through.
    _FILE_READ_CMDS = re.compile(
        r'^(?:cat|type|head|tail|less|more|grep|findstr|strings|xxd|od|hexdump|'
        r'file|stat|wc|nl|sort|uniq|cut|tr|sed|awk|base64|certutil|dd|'
        r'cp|copy|xcopy|robocopy|mv|move|tar|zip|7z|gzip|gunzip|scp|rsync|'
        r'find|dir|ls|get-content|get-item|select-string|'
        r'cat-file|show|diff)\b'
        r'(?P<rest>.*)$',
        re.IGNORECASE,
    )

    # Path-looking command arguments.  POSIX absolute (``/etc/x``),
    # home-relative (``~/x``), Windows absolute (``C:\\x``, ``C:/x``) and UNC
    # (``\\\\server\share``) forms are all recognised, bare or quoted, so a
    # drive letter cannot hide the target from the file rules.
    _PATH_IN_ARGS = re.compile(
        r'''(?:^|[\s'"=,:(])(?P<path>(?:[A-Za-z]:[\\/]|~[\\/]|\\\\|\$(?:HOME|\{HOME\})[\\/]|%USERPROFILE%[\\/])[^\s'"<>|;&,)]*|/(?![/*])[^\s'"<>|;&,)]*)'''
    )
    _QUOTED_PATH_IN_ARGS = re.compile(
        r'''['"](?P<path>(?:[A-Za-z]:[\\/]|~[\\/]|\\\\|\$(?:HOME|\{HOME\})[\\/]|%USERPROFILE%[\\/])[^'"]*|/(?![/*])[^'"]*)['"]'''
    )

    # Shell spellings of the home directory that ``os.path.expanduser`` misses.
    _SHELL_HOME_TOKENS = ("${HOME}", "$HOME", "%USERPROFILE%")

    @classmethod
    def _expand_shell_home(cls, candidate: str) -> str:
        for token in cls._SHELL_HOME_TOKENS:
            candidate = candidate.replace(token, "~")
        return candidate

    @staticmethod
    def _is_url_like(candidate: str) -> bool:
        return "://" in candidate or candidate.startswith("//")

    def _check_file_in_command(
        self,
        command: str,
        *,
        cwd: Optional[str] = None,
    ) -> Optional[RuleMatch]:
        """Cross-check read/write path arguments in a simple shell command."""
        try:
            tokens = self._shell_tokens(command)
        except ValueError:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Cannot safely parse shell path arguments",
                rule_type="command_file_parse",
            )
        if not tokens:
            return None

        name = os.path.basename(tokens[0]).casefold()
        read_commands = {
            "cat", "type", "head", "tail", "less", "more", "grep", "findstr",
            "strings", "xxd", "od", "hexdump", "file", "stat", "wc", "nl",
            "sort", "uniq", "cut", "tr", "sed", "awk", "base64", "certutil",
            "dd", "cp", "copy", "xcopy", "robocopy", "mv", "move", "tar",
            "zip", "7z", "gzip", "gunzip", "scp", "rsync", "find", "dir",
            "ls", "get-content", "get-item", "select-string", "cat-file",
            "show", "diff", "cd", "source", ".",
        }
        write_commands = {
            "touch", "mkdir", "rm", "unlink", "rmdir", "tee", "chmod",
            "chown", "ln", "mv", "move", "cp", "copy", "dd",
        }
        safe_write_commands = {"touch", "mkdir"}
        if name not in read_commands and name not in write_commands:
            return None

        checks: List[RuleMatch] = []
        indexed_checks: List[tuple[str, RuleMatch]] = []

        def check_path(raw_path: str, operation: str) -> bool:
            resolved = self._resolve_command_path(raw_path, cwd)
            if resolved is None or resolved == "/dev/null":
                return False
            match = self.check_file_path(resolved, operation)
            checks.append(match)
            indexed_checks.append((operation, match))
            return match.action == ActionType.DENY

        args = tokens[1:]
        positional = [
            token for token in args
            if token and token != "--" and not token.startswith("-")
        ]

        if name == "dd":
            for token in args:
                if token.startswith("if="):
                    check_path(token[3:], "read")
                elif token.startswith("of="):
                    check_path(token[3:], "write")
        elif name == "find":
            unsafe_actions = {
                "-exec", "-execdir", "-ok", "-okdir", "-delete",
                "-fprint", "-fprintf", "-fls",
            }
            if any(token in unsafe_actions for token in args):
                checks.append(
                    RuleMatch(
                        True,
                        ActionType.APPROVE,
                        "find with an executing/writing action requires approval",
                        rule_type="command_find_action",
                    )
                )
            if positional:
                check_path(positional[0], "traverse")
        elif name == "curl":
            for index, token in enumerate(args):
                if token in {
                    "-o", "--output",
                    "-c", "--cookie-jar",
                    "-D", "--dump-header",
                    "--trace", "--trace-ascii",
                    "--output-dir",
                } and index + 1 < len(args):
                    check_path(args[index + 1], "write")
            if any(token in {"-O", "--remote-name"} for token in args):
                checks.append(
                    RuleMatch(
                        True,
                        ActionType.APPROVE,
                        "curl remote-name output requires approval",
                        rule_type="command_curl_output",
                    )
                )
        elif name in {"chmod", "chown"}:
            for token in positional[1:]:
                check_path(token, "write")
        elif name in {"cp", "copy", "mv", "move", "ln"}:
            if positional:
                for source in positional[:-1]:
                    check_path(source, "read")
                check_path(positional[-1], "write")
        elif name in write_commands:
            for token in positional:
                check_path(token, "write")
        elif name == "cd":
            for token in positional[:1]:
                check_path(token, "traverse")
        elif name in {"ls", "dir"}:
            for token in positional:
                if token.isdigit():
                    continue
                check_path(token, "traverse")
        elif name in {
            "cat", "type", "head", "tail", "less", "more", "strings",
            "xxd", "od", "hexdump", "file", "stat", "wc", "nl", "sort",
            "uniq", "base64", "get-content", "get-item",
            "diff", "source",
        }:
            for token in positional:
                if token.isdigit():
                    continue
                check_path(token, "read")
        elif name in {
            "grep",
            "findstr",
            "select-string",
            "sed",
            "awk",
        }:
            if len(positional) >= 2:
                check_path(positional[-1], "read")
        else:
            for token in positional:
                if self._is_url_like(token):
                    continue
                resolved = self._resolve_command_path(token, cwd)
                path_like = (
                    token.startswith(("/", "~", "./", "../"))
                    or "/" in token
                    or (resolved is not None and os.path.exists(resolved))
                )
                if path_like:
                    check_path(token, "read")

        strongest = self._merge_command_matches(checks)
        if strongest is not None and strongest.action in {
            ActionType.DENY,
            ActionType.APPROVE,
        }:
            rule_type = (
                strongest.rule_type
                if strongest.rule_type
                in {
                    "task_scope_restriction",
                    "tool_scope_disabled",
                    "tool_scope_not_allowed",
                }
                else "command_file_check"
            )
            return RuleMatch(
                True,
                strongest.action,
                f"File access check: {strongest.reason}",
                strongest.pattern,
                rule_type,
            )

        if (
            name in safe_write_commands
            and indexed_checks
            and all(
                operation == "write" and match.action == ActionType.ALLOW
                for operation, match in indexed_checks
            )
        ):
            return RuleMatch(
                True,
                ActionType.ALLOW,
                "Write targets are inside allowed paths",
                rule_type="command_file_write_allowed",
            )
        return None

    def _check_network_in_command(self, command: str) -> Optional[RuleMatch]:
        """Apply network rules to URLs and network clients in shell commands."""
        try:
            tokens = self._shell_tokens(command)
        except ValueError:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                "Cannot safely parse shell network arguments",
                rule_type="command_network_parse",
            )
        if not tokens:
            return None

        name = os.path.basename(tokens[0]).casefold()
        urls = list(dict.fromkeys(
            match.group(0).rstrip(".,;")
            for match in re.finditer(r"https?://[^\s'\";|<>]+", command)
        ))
        if urls:
            checks = [self.check_network(url) for url in urls]
            strongest = self._merge_command_matches(checks)
            if strongest is not None and strongest.action in {
                ActionType.DENY,
                ActionType.APPROVE,
            }:
                return RuleMatch(
                    True,
                    strongest.action,
                    f"Network access check: {strongest.reason}",
                    strongest.pattern,
                    "command_network_check",
                )

            if name == "curl":
                unsafe_curl = any(
                    token in {
                        "-d", "--data", "--data-raw", "--data-binary",
                        "--data-urlencode", "--json", "-F", "--form",
                        "--form-string", "-T",
                        "--upload-file",
                    }
                    or token.startswith(("-d", "-F", "-T", "--request=", "--form"))
                    or (
                        token in {"-X", "--request"}
                        and index + 1 < len(tokens)
                        and tokens[index + 1].upper() not in {"GET", "HEAD"}
                    )
                    or (
                        token.startswith("-X")
                        and token[2:].upper() not in {"GET", "HEAD"}
                    )
                    for index, token in enumerate(tokens[1:], start=1)
                )
                if unsafe_curl:
                    return RuleMatch(
                        True,
                        ActionType.APPROVE,
                        "curl request can write or upload data; approval required",
                        rule_type="command_network_write",
                    )
                return RuleMatch(
                    True,
                    ActionType.ALLOW,
                    "curl target is in the allowed network list",
                    rule_type="command_network_allowed",
                )
            return None

        if name in {
            "curl", "wget", "http", "httpie", "nc", "ncat", "telnet",
            "socat", "ssh", "scp", "rsync",
        }:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                f"Network command '{name}' has no inspectable URL",
                rule_type="command_network_unresolved",
            )
        return None

    def _check_sensitive_shell_usage(self, command: str) -> Optional[RuleMatch]:
        try:
            tokens = self._shell_tokens(command)
        except ValueError:
            return None
        if not tokens:
            return None
        name = os.path.basename(tokens[0]).casefold()
        if name in {"env", "printenv"}:
            return RuleMatch(
                True,
                ActionType.APPROVE,
                f"'{name}' can expose environment secrets",
                rule_type="command_environment_exposure",
            )
        if name == "git":
            non_options = [
                token for token in tokens[1:] if not token.startswith("-")
            ]
            subcommand = non_options[0].casefold() if non_options else ""
            if subcommand == "branch" and len(non_options) > 1:
                return RuleMatch(
                    True,
                    ActionType.APPROVE,
                    "git branch mutation requires approval",
                    rule_type="command_git_write",
                )
            if subcommand == "remote" and len(non_options) > 1:
                return RuleMatch(
                    True,
                    ActionType.APPROVE,
                    "git remote mutation requires approval",
                    rule_type="command_git_write",
                )
            if subcommand == "config" and any(
                flag in tokens for flag in {"--add", "--unset", "--replace-all"}
            ):
                return RuleMatch(
                    True,
                    ActionType.APPROVE,
                    "git config mutation requires approval",
                    rule_type="command_git_write",
                )
        return None

    # Interpreter → temp file extension mapping
    _INTERP_EXT = {
        'python': '.py', 'python3': '.py', 'pypy': '.py', 'pypy3': '.py',
        'bash': '.sh', 'sh': '.sh', 'zsh': '.sh', 'fish': '.sh',
        'node': '.js', 'nodejs': '.js', 'ts-node': '.ts',
        'perl': '.pl', 'ruby': '.rb',
        'powershell': '.ps1', 'pwsh': '.ps1', 'cmd': '.bat',
    }

    # Matches: interpreter [flags] -c/-e/-command 'code' or "code" or bare code
    _INLINE_SCRIPT_RE = re.compile(
        r'^(?P<interp>python3?|pypy3?|node|nodejs|ts-node|bash|sh|zsh|fish|perl|ruby|powershell|pwsh|cmd)'
        r'(?:\s+[/-][^ce\s]\S*)*'          # optional other flags (never -c/-e/-command)
        r'\s+[/-](?:c|e|command)\s+'
        r'(?P<code>.+)$',
        re.DOTALL | re.IGNORECASE,
    )

    def _check_inline_script(self, command: str) -> Optional[RuleMatch]:
        """
        If *command* is an interpreter invoked with -c/-e <inline code>,
        write the inline string to a temp file and run ScriptAnalyzer on it.
        Returns a RuleMatch on findings, or None to continue normal processing.
        """
        import tempfile

        m = self._INLINE_SCRIPT_RE.match(command.strip())
        if not m:
            return None

        interp = m.group('interp')
        raw_code = m.group('code').strip()

        # Strip surrounding quotes (single, double, or none)
        if len(raw_code) >= 2 and raw_code[0] in ('"', "'") and raw_code[-1] == raw_code[0]:
            code = raw_code[1:-1]
        else:
            code = raw_code

        if not code:
            return None

        ext = self._INTERP_EXT.get(interp, '.sh')

        # Write to temp file, analyse, then delete immediately
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix=ext, delete=False, encoding='utf-8'
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            result = self.script_analyzer.analyze(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        if result.recommended_action == 'deny':
            findings_text = '; '.join(
                f"{f.severity.upper()} [{f.category}] {f.description}"
                + (f" (line {f.line})" if f.line else "")
                for f in result.findings
            )
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=(
                    f"🚨 Inline script DENIED ({interp} -c): {result.summary} "
                    f"— {findings_text}"
                ),
                rule_type="inline_script_analysis",
            )

        if result.recommended_action == 'approve':
            findings_text = '; '.join(
                f"{f.severity.upper()} [{f.category}] {f.description}"
                + (f" (line {f.line})" if f.line else "")
                for f in result.findings
            )
            return RuleMatch(
                matched=True,
                action=ActionType.APPROVE,
                reason=(
                    f"⚠️ Inline script requires approval ({interp} -c): "
                    f"{result.summary} — {findings_text}"
                ),
                rule_type="inline_script_analysis",
            )

        return None

    # Interpreters whose first positional argument is a script file
    _SCRIPT_INTERPRETERS = re.compile(
        r'^(?P<interp>python3?|pypy3?|node|nodejs|ts-node|bash|sh|zsh|fish|perl|ruby|powershell|pwsh|cmd)'
        r'\s+(?P<flags>(?:-[^\s]+\s+)*)'
        r'(?P<script>[^\s|;&><]+\.(?:py|js|mjs|ts|sh|bash|zsh|fish|rb|pl|ps1|bat|cmd))'
        r'(?:\s+.*)?$',
        re.IGNORECASE,
    )

    def _check_script_in_command(self, command: str) -> Optional[RuleMatch]:
        """
        If *command* invokes an interpreter with a script file, run ScriptAnalyzer
        on that file and return a RuleMatch.  Returns None if the command does not
        match the interpreter pattern (so normal rule processing continues).
        """
        m = self._SCRIPT_INTERPRETERS.match(command.strip())
        if not m:
            return None

        script_path = m.group('script')
        result = self.script_analyzer.analyze(script_path)

        if result.recommended_action == 'deny':
            findings_text = '; '.join(
                f"{f.severity.upper()} [{f.category}] {f.description}"
                + (f" (line {f.line})" if f.line else "")
                for f in result.findings
            )
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=(
                    f"🚨 Script analysis DENIED '{script_path}': {result.summary} "
                    f"— {findings_text}"
                ),
                rule_type="script_analysis",
            )

        if result.recommended_action == 'approve':
            findings_text = '; '.join(
                f"{f.severity.upper()} [{f.category}] {f.description}"
                + (f" (line {f.line})" if f.line else "")
                for f in result.findings
            )
            return RuleMatch(
                matched=True,
                action=ActionType.APPROVE,
                reason=(
                    f"⚠️ Script analysis requires approval for '{script_path}': "
                    f"{result.summary} — {findings_text}"
                ),
                rule_type="script_analysis",
            )

        # result.recommended_action == 'allow' → fall through to normal rule processing
        return None

    # ================================
    # File Rules
    # ================================
    
    def check_file_path(self, path: str, operation: str = "read") -> RuleMatch:
        """Require the file target to satisfy base policy and task scope."""
        base = self._base_file_match(path, operation)
        scope_result = self._check_task_scope_file(path, operation)
        return self._combine_base_and_scope(
            base,
            scope_result,
            operation=f"file {operation}",
        )

    def _base_file_match(self, path: str, operation: str = "read") -> RuleMatch:
        """
        Check file path access
        
        Args:
            path: File path
            operation: Operation type (read/write)
            
        Returns:
            RuleMatch: Match result
        """
        expanded_path = os.path.expanduser(path)

        # Resolve symlinks to prevent symlink attacks (e.g. /tmp/x -> /etc/passwd).
        # realpath() follows the full chain; if the path doesn't exist yet (new file
        # write), it resolves as far as possible and leaves the final component as-is.
        real_path = os.path.realpath(expanded_path)

        # Detect dangling symlinks — the expanded path exists as a symlink but
        # realpath didn't resolve to an existing file.  Deny as a safety default.
        if os.path.islink(expanded_path) and not os.path.exists(real_path):
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=f"Dangling symlink denied: {path} → target does not exist",
                rule_type="file_dangling_symlink",
            )

        abs_path = real_path

        # 1. Check denied paths (ALWAYS first — task scope cannot override)
        for denied in self.file_rules["denied_paths"]:
            denied_expanded = os.path.expanduser(denied)
            # Compare the resolved entry as well: on Linux a denied directory
            # is often a symlink, and only matching the written spelling would
            # leave its real location readable.
            for candidate in dict.fromkeys(
                (denied_expanded, os.path.realpath(denied_expanded))
            ):
                if (
                    self._path_is_within(abs_path, candidate)
                    or fnmatch.fnmatch(abs_path, candidate)
                    or (
                        candidate.endswith("/**")
                        and self._path_is_within(abs_path, candidate[:-3])
                    )
                ):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.DENY,
                        reason=f"Path in denied list: {denied}",
                        rule_type="file_denied",
                    )
        
        # Task scope is applied by the public wrapper after this base chain.
        
        # 3. Check sensitive file patterns
        for pattern in self.file_rules["sensitive_patterns"]:
            pattern_expanded = os.path.expanduser(pattern)
            if fnmatch.fnmatch(abs_path, pattern_expanded):
                return RuleMatch(
                    matched=True,
                    action=ActionType.APPROVE,
                    reason=f"Sensitive file: {pattern}",
                    rule_type="file_sensitive",
                )
        
        # 4. Check allowed paths
        for allowed in self.file_rules["allowed_paths"]:
            allowed_expanded = os.path.expanduser(allowed)
            # Support wildcards
            if "*" in allowed_expanded:
                if fnmatch.fnmatch(abs_path, allowed_expanded):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.ALLOW,
                        reason="Path in allowed list",
                        rule_type="file_allowed",
                    )
            elif self._path_is_within(
                abs_path,
                os.path.realpath(allowed_expanded),
            ):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason="Path in allowed list",
                    rule_type="file_allowed",
                )
        
        # 5. Default: supervised
        return RuleMatch(
            matched=False,
            action=ActionType.APPROVE,
            reason="Path not in allowed list, requires approval",
            rule_type="file_unknown",
        )

    @staticmethod
    def _path_is_within(path: str, root: str) -> bool:
        """Return True when *path* is *root* or a descendant of it.

        A plain ``startswith`` check makes ``/workspace_evil`` a child of
        ``/workspace``.  ``commonpath`` enforces a real directory boundary,
        which is required for allow-list decisions and keeps deny-list
        matching precise.
        """
        try:
            return os.path.commonpath((path, root)) == root
        except ValueError:
            # Different drives on Windows cannot share a common path.
            return False
    
    # ================================
    # Network Rules
    # ================================
    
    def check_network(self, url: str) -> RuleMatch:
        """Require the network target to satisfy base policy and task scope."""
        base = self._base_network_match(url)
        scope_result = self._check_task_scope_network(url)
        return self._combine_base_and_scope(
            base,
            scope_result,
            operation="network request",
        )

    def _base_network_match(self, url: str) -> RuleMatch:
        """
        Check network request
        
        Args:
            url: Target URL
            
        Returns:
            RuleMatch: Match result
        """
        parsed = urlparse(url)
        # Match on the hostname rather than the netloc so an explicit port
        # cannot slip past the metadata block, the private-IP block, the
        # deny-list, or the allow-list (e.g. http://127.0.0.1:8080/).
        domain = (parsed.hostname or parsed.netloc or "").lower()
        scheme = parsed.scheme.lower()
        
        # 0. Block non-HTTP protocols (SSRF prevention) — ALWAYS checked first
        if scheme not in ['http', 'https', '']:
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=f"🚨 CRITICAL: Non-HTTP protocol blocked: {scheme}://",
                rule_type="network_protocol_blocked",
            )
        
        # 0.1 Block metadata endpoints (AWS, GCP, Azure)
        metadata_endpoints = [
            '169.254.169.254',  # AWS/Azure
            'metadata.google.internal',  # GCP
            'metadata.goog',  # GCP alternative
            '100.100.100.200',  # Alibaba Cloud
            'fd00:ec2::254',  # AWS IPv6
        ]
        
        for endpoint in metadata_endpoints:
            if endpoint in domain:
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=f"🚨 CRITICAL: Cloud metadata endpoint blocked: {endpoint}",
                    rule_type="network_metadata_blocked",
                )
        
        # 0.2 Block private IP ranges (RFC1918 + localhost)
        if self._is_private_ip(domain):
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=f"🚨 CRITICAL: Private IP/localhost blocked: {domain}",
                rule_type="network_private_ip_blocked",
            )
        
        # 1. Check denied domains
        for denied in self.network_rules["denied_domains"]:
            if self._match_domain(domain, denied):
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=f"Domain in denied list: {denied}",
                    rule_type="network_denied",
                )
        
        # Task scope is applied by the public wrapper after this base chain.
        
        # 3. Check allowed domains
        for allowed in self.network_rules["allowed_domains"]:
            if self._match_domain(domain, allowed):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason="Domain in whitelist",
                    rule_type="network_allowed",
                )
        
        # 4. Default action
        return RuleMatch(
            matched=False,
            action=self.network_rules["default_action"],
            reason="Domain not in whitelist",
            rule_type="network_default",
        )
    
    def _is_private_ip(self, domain: str) -> bool:
        """Check if domain is a private IP or localhost"""
        import ipaddress
        import re
        
        # Remove port if present
        host = domain.split(':')[0]
        
        # Check for localhost names
        localhost_names = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        if host.lower() in localhost_names:
            return True
        
        # Check if it's an IP address
        ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$|^\[?([0-9a-fA-F:]+)\]?$'
        if re.match(ip_pattern, host):
            try:
                # Remove brackets for IPv6
                ip_str = host.strip('[]')
                ip = ipaddress.ip_address(ip_str)
                
                # Check if private, loopback, or link-local
                return (ip.is_private or ip.is_loopback or 
                        ip.is_link_local or ip.is_reserved)
            except ValueError:
                # Not a valid IP, skip
                pass
        
        return False
    
    def _match_domain(self, domain: str, pattern: str) -> bool:
        """Match domain (supports wildcards)"""
        pattern = pattern.lower()
        if pattern.startswith("*."):
            # Wildcard subdomain
            suffix = pattern[2:]
            return domain == suffix or domain.endswith("." + suffix)
        return domain == pattern
    
    # ================================
    # ================================
    # Task Scope (Per-Prompt Least-Privilege)
    # ================================
    
    @staticmethod
    def _matches_disabled_set(tool_name: str, disabled: Any) -> bool:
        """Alias-aware membership test against one disabled-tool list."""

        disabled_names = {str(item or "").strip().casefold() for item in disabled or []}
        if not disabled_names:
            return False
        if tool_name in disabled_names:
            return True
        return any(
            tool_name in aliases and aliases & disabled_names
            for aliases in _TOOL_ALIAS_GROUPS
        )

    def _is_explicitly_allowed(self, tool_name: str) -> bool:
        """Return whether the scope's own allowlist names this exact tool."""

        allowed = self.task_scope_rules.get("allowed_tools")
        if not isinstance(allowed, list):
            return False
        return tool_name in {str(item or "").strip().casefold() for item in allowed}

    def is_tool_disabled(self, tool: str) -> bool:
        """
        Check if a tool is disabled by the active task scope.

        Explicit declarations always deny.  Category-derived disables (see
        ``set_task_scope``) apply only to tools the scope did not explicitly
        allow: a planner that selects ``web_search`` while declaring no
        network host must not have that choice revoked by the empty-network
        inference, because the network rules still block the real
        destination.  Legacy scopes carry only the merged list and keep their
        original behavior.
        """
        if not self.task_scope_active:
            return False

        rules = self.task_scope_rules
        explicit = rules.get("explicit_disabled_tools")
        inferred = rules.get("inferred_disabled_tools")
        if explicit is None and inferred is None:
            explicit = rules.get("disabled_tools", [])
            inferred = []

        tool_name = str(tool or "").strip().casefold()
        if not explicit and not inferred:
            return False
        if self._matches_disabled_set(tool_name, explicit):
            return True
        if self._matches_disabled_set(tool_name, inferred):
            return not self._is_explicitly_allowed(tool_name)
        return False

    def is_tool_allowed(self, tool: str) -> bool:
        """Return whether an active scope permits this exact model tool.

        Legacy/manual scopes leave ``allowed_tools`` as ``None`` and retain
        their historical behavior.  Gateway-created scopes always provide a
        list, so an empty list denies every model tool and aliases do not
        accidentally grant one another.
        """
        if not self.task_scope_active:
            return True
        allowed = self.task_scope_rules.get("allowed_tools")
        if allowed is None:
            return True
        allowed_names = {str(item or "").strip().casefold() for item in allowed}
        return str(tool or "").strip().casefold() in allowed_names
    
    def set_task_scope(
        self,
        task_description: str,
        file_read: List[str] = None,
        file_write: List[str] = None,
        directory_list: List[str] = None,
        commands: List[str] = None,
        network: List[str] = None,
        disabled_tools: List[str] = None,
        allowed_tools: Optional[List[str]] = None,
        capability_adapters: bool = False,
    ) -> Dict[str, Any]:
        """
        Set task scope - inject temporary per-task rules on top of base rules.
        Task scope can only further restrict, never override base denials.
        
        Args:
            task_description: Brief description of the task
            file_read: Allowed file paths for reading (supports globs)
            file_write: Allowed file paths for writing
            directory_list: Allowed directory roots for metadata-only listing
            commands: Allowed command prefixes
            network: Allowed network domains
            disabled_tools: Tools to completely disable
            
        Returns:
            Dict with applied scope details
        """
        # Reject if locked to base rules only
        if self.task_scope_locked:
            return {
                "error": "Task scope is locked — base rules only mode is active. Unlock from the dashboard to allow task scope.",
                "locked": True,
            }
        
        _commands = commands or []
        _network = network or []
        _file_write = file_write or []
        _file_read = file_read or []
        _directory_list = directory_list or []

        # Explicit declarations are absolute.  The category-derived entries
        # below only cover capabilities the caller left undeclared, so they
        # must not revoke a tool that ``allowed_tools`` names explicitly.
        explicit_disabled = list(dict.fromkeys(
            str(item).strip() for item in (disabled_tools or []) if str(item).strip()
        ))
        inferred_disabled = set()
        if not _commands:
            inferred_disabled.add("execute_command")
        if not _network:
            inferred_disabled.add("http_request")
        if not _file_write:
            inferred_disabled.add("write_file")
            inferred_disabled.add("edit_file")

        allowed_capabilities = self._derive_task_scope_capabilities(
            allowed_tools,
            _file_read,
            _file_write,
            _network,
            _commands,
        )
        expanded_commands = list(_commands)
        if capability_adapters:
            adapter_commands = []
            if "file_read" in allowed_capabilities:
                adapter_commands.extend([
                    "cat", "head", "tail", "less", "more", "grep",
                    "strings", "xxd", "od", "hexdump", "file", "stat",
                    "wc", "nl", "sort", "uniq", "base64", "ls", "dir", "find",
                ])
            if "file_write" in allowed_capabilities:
                adapter_commands.extend([
                    "touch", "mkdir", "tee", "cp", "mv", "chmod",
                    "chown", "ln", "rm", "echo", "printf",
                ])
            if "network_read" in allowed_capabilities:
                adapter_commands.extend([
                    "curl", "wget", "grep", "head", "tail", "sort", "uniq", "find",
                    "cut", "tr", "wc",
                ])
            expanded_commands = list(dict.fromkeys(
                expanded_commands + adapter_commands
            ))

        self.task_scope_active = True
        expanded_read = self._expand_paths(_file_read)
        expanded_write = self._expand_paths(_file_write)
        self.task_scope_rules = {
            "file_traverse": self._derive_task_scope_traversals(
                expanded_read + expanded_write,
                _commands,
            ),
            "directory_list": self._expand_paths(_directory_list),
            "file_read": expanded_read,
            "file_write": expanded_write,
            "commands": expanded_commands,
            "declared_commands": _commands,
            "network": _network,
            "allowed_capabilities": allowed_capabilities,
            "capability_adapters": bool(capability_adapters),
            # Merged view retained for the Dashboard and for callers that only
            # understand the original single list.
            "disabled_tools": list(dict.fromkeys(
                explicit_disabled + sorted(inferred_disabled)
            )),
            "explicit_disabled_tools": explicit_disabled,
            "inferred_disabled_tools": sorted(inferred_disabled),
            "allowed_tools": (
                None
                if allowed_tools is None
                else list(dict.fromkeys(str(item).strip() for item in allowed_tools if str(item).strip()))
            ),
        }

        return {
            "task_description": task_description,
            "scope_active": True,
            "locked": self.task_scope_locked,
            "rules": self.task_scope_rules,
        }
    
    def lock_task_scope(self) -> Dict[str, Any]:
        """
        Lock task scope so only base rules apply.
        Refuses to lock while a task scope is currently active.
        """
        if self.task_scope_active:
            return {
                "error": "Cannot lock task scope while a task scope is active. Clear the current scope first.",
                "locked": self.task_scope_locked,
                "scope_active": self.task_scope_active,
            }
        
        self.task_scope_locked = True
        return {
            "locked": True,
            "scope_active": False,
            "message": "Task scope locked — base rules only mode is active",
        }
    
    def unlock_task_scope(self) -> Dict[str, Any]:
        """
        Unlock task scope so agents may set per-task restrictions again.
        """
        self.task_scope_locked = False
        return {
            "locked": False,
            "scope_active": self.task_scope_active,
            "message": "Task scope unlocked",
        }
    
    def clear_task_scope(self) -> Dict[str, Any]:
        """
        Clear task scope - remove all per-task restrictions.
        Base rules still apply.
        
        Returns:
            Dict with cleared scope status
        """
        self.task_scope_active = False
        self.task_scope_rules = {
            "file_traverse": [],
            "directory_list": [],
            "file_read": [],
            "file_write": [],
            "commands": [],
            "network": [],
            "allowed_capabilities": [],
            "capability_adapters": False,
            "disabled_tools": [],
            "explicit_disabled_tools": [],
            "inferred_disabled_tools": [],
            "allowed_tools": None,
        }
        
        return {
            "scope_active": False,
            "locked": self.task_scope_locked,
            "message": "Task scope cleared",
        }
    
    def _check_task_scope_file(self, path: str, operation: str) -> Optional[RuleMatch]:
        """
        Check file access against the active task scope.

        Returns None when the scope is inactive (base rules alone decide).
        Returns ALLOW when the scope declares the path, and DENY when the
        scope is active but does not cover it.
        """
        if not self.task_scope_active:
            return None
        
        def scope_path(value: str) -> str:
            expanded = os.path.expanduser(os.path.expandvars(value))
            if not os.path.isabs(expanded):
                expanded = os.path.join(self.command_working_dir, expanded)
            return os.path.realpath(os.path.abspath(expanded))

        expanded_path = scope_path(path)
        scope_paths = list(self.task_scope_rules.get(f"file_{operation}", []))
        if operation == "traverse":
            scope_paths = list(
                dict.fromkeys(
                    scope_paths
                    + list(self.task_scope_rules.get("directory_list") or [])
                )
            )
        
        # If scope list is empty, nothing is allowed
        if not scope_paths:
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason=f"Task scope: no {operation} paths declared",
                rule_type="task_scope",
            )
        
        # Check if path matches any allowed scope path (supports globs)
        for allowed in scope_paths:
            # Make relative declarations comparable to the resolved target;
            # keep wildcard components intact for fnmatch.
            expanded_allowed = scope_path(allowed)
            
            # Exact match
            if expanded_path == expanded_allowed:
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason=f"Task scope: {operation} allowed for this path",
                    rule_type="task_scope",
                )
            
            # Glob match (e.g., ~/project/**)
            if "*" in expanded_allowed:
                if fnmatch.fnmatch(expanded_path, expanded_allowed):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.ALLOW,
                        reason=f"Task scope: {operation} allowed by glob pattern",
                        rule_type="task_scope",
                    )
                # ~/project/** should also allow the directory itself (~/project)
                base = expanded_allowed.rstrip("/*")
                if expanded_path == base or expanded_path.startswith(base + os.sep):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.ALLOW,
                        reason=f"Task scope: {operation} allowed by glob pattern",
                        rule_type="task_scope",
                    )
            
            # Directory prefix match (e.g., ~/project allows ~/project/file.txt)
            if expanded_path.startswith(expanded_allowed + os.sep):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason=f"Task scope: {operation} allowed by directory scope",
                    rule_type="task_scope",
                )
        
        # Not in scope — deny immediately
        return RuleMatch(
            matched=True,
            action=ActionType.DENY,
            reason=f"Task scope: {operation} not allowed for this path",
            rule_type="task_scope",
        )
    
    def _check_task_scope_command(
        self,
        command: str,
        *,
        shell_analyzed: bool = False,
    ) -> Optional[RuleMatch]:
        """
        Check a command against the active task scope.

        Returns None when the scope is inactive (base rules alone decide).
        Returns ALLOW when the scope declares the command, and DENY when the
        scope is active but does not cover it.
        """
        if not self.task_scope_active:
            return None
        
        scope_commands = self.task_scope_rules.get("commands", [])
        
        # If scope list is empty, no commands allowed
        if not scope_commands:
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason="Task scope: no commands declared",
                rule_type="task_scope",
            )
        
        normalized_command = command.strip()
        # A prefix may authorize ordinary arguments (``pytest -q``), but not
        # shell chaining/redirection that can append an unrelated operation.
        # Such compound commands require the exact full command to have been
        # declared in the scope.
        shell_control = re.compile(r"[;&|<>`\r\n]")
        for allowed_prefix in scope_commands:
            prefix = str(allowed_prefix or "").strip()
            if not prefix:
                continue
            prefix_match = normalized_command == prefix or normalized_command.startswith(prefix + " ")
            if prefix_match and (
                normalized_command == prefix
                or shell_analyzed
                or not shell_control.search(normalized_command)
            ):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason=f"Task scope: command allowed by prefix '{prefix}'",
                    rule_type="task_scope",
                )
        
        # Not in scope
        return RuleMatch(
            matched=True,
            action=ActionType.DENY,
            reason="Task scope: command not in allowed list",
            rule_type="task_scope",
        )
    
    def _check_task_scope_network(self, url: str) -> Optional[RuleMatch]:
        """
        Check a network destination against the active task scope.

        Returns None when the scope is inactive (base rules alone decide).
        Returns ALLOW when the scope declares the host, and DENY when the scope
        is active but does not cover it.  Base denials are applied before this
        check, so a deny-listed host or a blocked address stays blocked.
        """
        if not self.task_scope_active:
            return None
        
        scope_domains = self.task_scope_rules.get("network", [])
        
        # If scope list is empty, no network allowed
        if not scope_domains:
            return RuleMatch(
                matched=True,
                action=ActionType.DENY,
                reason="Task scope: no network domains declared",
                rule_type="task_scope",
            )
        
        # Extract the hostname (not netloc) so ordinary explicit ports do not
        # prevent a declared host from matching the same site.
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower().rstrip(".")
        
        # Check if domain matches any allowed scope domain
        for allowed in scope_domains:
            if self._match_domain(domain, allowed):
                # Scope-declared domain — grant it for this task.
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason=f"Task scope: domain '{domain}' declared in scope",
                    rule_type="task_scope",
                )
        
        # Not in scope.  Name the offending host: the audit trail stores only a
        # hash of the tool arguments, so without it a denial cannot be explained
        # after the fact.
        declared = ", ".join(str(item) for item in scope_domains)
        return RuleMatch(
            matched=True,
            action=ActionType.DENY,
            reason=(
                f"Task scope: host '{domain or url}' is not in the declared scope "
                f"[{declared}]"
            ),
            rule_type="task_scope",
        )
    
    @classmethod
    def from_config(cls, config_path: str) -> "RuleEngine":
        """Create instance from config file"""
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return cls(config)
