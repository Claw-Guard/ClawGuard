"""
Rule Engine Module (Rule Engine Module)
Responsible for command, file, and network rule matching and decision
"""

import re
import os
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
        
        if rules_config:
            self._load_rules(rules_config)
    
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
    
    # ================================
    # Command Rules
    # ================================
    
    def check_command(self, command: str) -> RuleMatch:
        """
        Check command
        
        Args:
            command: Command
            
        Returns:
            RuleMatch: Match result
        """
        # ── Script analysis (runs BEFORE whitelist/blacklist) ────────────────
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
        file_result = self._check_file_in_command(command)
        if file_result is not None:
            return file_result

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
            # 1. Check blacklist first (highest priority)
            for rule in self.command_rules["blacklist"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.DENY,
                        reason=rule["reason"],
                        pattern=rule["raw_pattern"],
                        rule_type="command_blacklist",
                    )
            
            # 2. Check whitelist (allow)
            for rule in self.command_rules["whitelist"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.ALLOW,
                        reason="Command in whitelist",
                        pattern=rule["raw_pattern"],
                        rule_type="command_whitelist",
                    )
            
            # 3. Check supervised list
            for rule in self.command_rules["supervised"]:
                if rule["pattern"].search(cmd_to_check):
                    return RuleMatch(
                        matched=True,
                        action=ActionType.APPROVE,
                        reason=rule["reason"],
                        pattern=rule["raw_pattern"],
                        rule_type="command_supervised",
                    )
        
        # 4. DefaultAllow
        return RuleMatch(
            matched=False,
            action=ActionType.ALLOW,
            reason="Command did not match any rules，DefaultAllow",
            rule_type="command_default",
        )
    
    # ================================
    # Script Analysis (helper)
    # ================================

    # Commands that read file content — extract path arg and run file rules
    _FILE_READ_CMDS = re.compile(
        r'^(?:cat|head|tail|less|more|grep|strings|xxd|od|hexdump|file|stat|wc)'  # read-ish commands
        r'(?P<rest>.+)$'
    )
    _PATH_IN_ARGS = re.compile(r'(?:^|\s)(?P<path>(?:/|~/)[^\s;|&><]+)')

    def _check_file_in_command(self, command: str) -> Optional[RuleMatch]:
        """
        If *command* is a file-reading command targeting a path, run check_file_path
        on that path.  Returns a RuleMatch only when the path is DENIED or SENSITIVE;
        returns None for allowed paths (so normal whitelist logic continues).
        """
        m = self._FILE_READ_CMDS.match(command.strip())
        if not m:
            return None

        # Find all absolute/home-relative paths in the argument string
        paths = self._PATH_IN_ARGS.findall(m.group('rest'))
        if not paths:
            return None

        # Check each path — deny/approve on first hit
        for path in paths:
            result = self.check_file_path(path, operation='read')
            if result.action == ActionType.DENY:
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=f"File access denied: {path} ({result.reason})",
                    rule_type="command_file_check",
                )
            if result.action == ActionType.APPROVE:
                return RuleMatch(
                    matched=True,
                    action=ActionType.APPROVE,
                    reason=f"File access requires approval: {path} ({result.reason})",
                    rule_type="command_file_check",
                )
        return None

    # Interpreter → temp file extension mapping
    _INTERP_EXT = {
        'python': '.py', 'python3': '.py', 'pypy': '.py', 'pypy3': '.py',
        'bash': '.sh', 'sh': '.sh', 'zsh': '.sh', 'fish': '.sh',
        'node': '.js', 'nodejs': '.js', 'ts-node': '.ts',
        'perl': '.pl', 'ruby': '.rb',
    }

    # Matches: interpreter [flags] -c/-e 'code' or "code" or bare code
    _INLINE_SCRIPT_RE = re.compile(
        r'^(?P<interp>python3?|pypy3?|node|nodejs|ts-node|bash|sh|zsh|fish|perl|ruby)'
        r'(?:\s+(?:-[^ce\s]\S*\s+)*)+'   # optional other flags
        r'-[ce]\s+'
        r'(?P<code>.+)$',
        re.DOTALL,
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
        r'^(?P<interp>python3?|pypy3?|node|nodejs|ts-node|bash|sh|zsh|fish|perl|ruby)'
        r'\s+(?P<flags>(?:-[^\s]+\s+)*)'
        r'(?P<script>[^\s|;&><]+\.(?:py|js|mjs|ts|sh|bash|zsh|fish|rb|pl))'
        r'(?:\s+.*)?$'
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

        # 1. Check denied paths
        for denied in self.file_rules["denied_paths"]:
            denied_expanded = os.path.expanduser(denied)
            if abs_path.startswith(denied_expanded) or fnmatch.fnmatch(abs_path, denied_expanded):
                return RuleMatch(
                    matched=True,
                    action=ActionType.DENY,
                    reason=f"Path in denied list: {denied}",
                    rule_type="file_denied",
                )
        
        # 2. Check sensitive file patterns
        for pattern in self.file_rules["sensitive_patterns"]:
            pattern_expanded = os.path.expanduser(pattern)
            if fnmatch.fnmatch(abs_path, pattern_expanded):
                return RuleMatch(
                    matched=True,
                    action=ActionType.APPROVE,
                    reason=f"Sensitive file: {pattern}",
                    rule_type="file_sensitive",
                )
        
        # 3. Check allowed paths
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
            elif abs_path.startswith(allowed_expanded):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason="Path in allowed list",
                    rule_type="file_allowed",
                )
        
        # 4. Default: supervised
        return RuleMatch(
            matched=False,
            action=ActionType.APPROVE,
            reason="Path not in allowed list, requires approval",
            rule_type="file_unknown",
        )
    
    # ================================
    # Network Rules
    # ================================
    
    def check_network(self, url: str) -> RuleMatch:
        """
        Check network request
        
        Args:
            url: Target URL
            
        Returns:
            RuleMatch: Match result
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        scheme = parsed.scheme.lower()
        
        # 0. Block non-HTTP protocols (SSRF prevention)
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
        
        # 2. Check allowed domains
        for allowed in self.network_rules["allowed_domains"]:
            if self._match_domain(domain, allowed):
                return RuleMatch(
                    matched=True,
                    action=ActionType.ALLOW,
                    reason="Domain in whitelist",
                    rule_type="network_allowed",
                )
        
        # 3. Default action
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
    
    @classmethod
    def from_config(cls, config_path: str) -> "RuleEngine":
        """Create instance from config file"""
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return cls(config)