"""
Skill Security Check Module (Skill Checker Module)
Pre-check if operations are compliant before Agent execution
"""

import re
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import yaml


class SkillCheckResult(Enum):
    """Skill Check Result"""
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


@dataclass
class SkillCheckResponse:
    """Skill Check Response"""
    result: str
    reason: str
    skill_name: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result,
            "reason": self.reason,
            "skill_name": self.skill_name,
            "action": self.action,
            "details": self.details,
        }


class SkillChecker:
    """
    Skill Security Checker
    
    Features:
    - Check if Skill is in trust list
    - Check if Skill operations are compliant
    - Return allow/deny/warn + reason
    """
    
    # Default trusted Skills
    DEFAULT_TRUSTED = [
        "@anthropic/claude-code",
        "@openclaw/*",
        "skill-creator",
        "github",
        "weather",
    ]
    
    # DefaultWarningOperation
    DEFAULT_UNTRUSTED_ACTIONS = [
        {
            "pattern": "network_request",
            "reason": "NetworkDomain",
        },
        {
            "pattern": "file_write",
            "reason": "FileWritePath",
        },
        {
            "pattern": "command_exec",
            "reason": "Command",
        },
        {
            "pattern": "shell_exec",
            "reason": "Shell Command",
        },
    ]
    
    def __init__(
        self,
        trusted_skills: Optional[List[str]] = None,
        untrusted_actions: Optional[List[Dict]] = None,
    ):
        """
        Initialize Skill Checker
        
        Args:
            trusted_skills: Trusted Skill List（）
            untrusted_actions: WarningOperationList
        """
        self.trusted_skills = trusted_skills or self.DEFAULT_TRUSTED
        self.untrusted_actions = untrusted_actions or self.DEFAULT_UNTRUSTED_ACTIONS
        
        # 
        self._trusted_patterns = []
        for skill in self.trusted_skills:
            if "*" in skill:
                # 
                pattern = skill.replace("*", ".*")
                self._trusted_patterns.append(re.compile(f"^{pattern}$"))
    
    def check_skill(
        self,
        skill_identifier: str,
        skill_name: Optional[str] = None,
        action: Optional[str] = None,
    ) -> SkillCheckResponse:
        """
         Skill 
        
        Args:
            skill_identifier: Skill （ @anthropic/claude-code）
            skill_name: Skill （）
            action: Operation（）
            
        Returns:
            SkillCheckResponse: Result
        """
        # 1. Trust listin
        if self._is_trusted(skill_identifier):
            # Trusted Skill，Operation
            if action:
                action_check = self._check_action(action)
                if action_check:
                    return SkillCheckResponse(
                        result=SkillCheckResult.WARN.value,
                        reason=action_check["reason"],
                        skill_name=skill_identifier,
                        action=action,
                    )
            
            return SkillCheckResponse(
                result=SkillCheckResult.ALLOW.value,
                reason="Skill Trust listin",
                skill_name=skill_identifier,
                action=action,
            )
        
        # 2. not inTrust listin，Warning
        return SkillCheckResponse(
            result=SkillCheckResult.WARN.value,
            reason=f"Skill '{skill_identifier}' not inTrust listin，",
            skill_name=skill_identifier,
            action=action,
            details={
                "trusted_skills": self.trusted_skills,
            },
        )
    
    def _is_trusted(self, skill_identifier: str) -> bool:
        """Check if Skill is in trust list"""
        # 
        if skill_identifier in self.trusted_skills:
            return True
        
        # 
        for pattern in self._trusted_patterns:
            if pattern.match(skill_identifier):
                return True
        
        return False
    
    def _check_action(self, action: str) -> Optional[Dict]:
        """OperationWarning"""
        for untrusted in self.untrusted_actions:
            if untrusted["pattern"] in action:
                return untrusted
        return None
    
    def check_operation(
        self,
        operation_type: str,
        operation_detail: str,
        skill_identifier: Optional[str] = None,
    ) -> SkillCheckResponse:
        """
        Operation
        
        Args:
            operation_type: OperationType（command, file, network）
            operation_detail: Operation
            skill_identifier:  Skill
            
        Returns:
            SkillCheckResponse: Result
        """
        # DangerousOperation
        dangerous_patterns = {
            "command": [
                (r"rm\s+-rf", "Dangerous：Command"),
                (r"sudo\s+", "Warning： root "),
                (r"chmod\s+777", "Warning："),
                (r">\s*/dev/", "Dangerous：FileWrite"),
            ],
            "file": [
                (r"\.ssh/", "：SSH "),
                (r"\.env", "：File"),
                (r"credentials", "：Credential file"),
                (r"\.pem$|\.key$", "：File"),
            ],
            "network": [
                (r"\.onion", "Warning：Tor Network"),
                (r"pastebin\.com", "Warning：Code sharing website"),
                (r"ngrok\.io", "Warning："),
            ],
        }
        
        patterns = dangerous_patterns.get(operation_type, [])
        
        for pattern, reason in patterns:
            if re.search(pattern, operation_detail):
                return SkillCheckResponse(
                    result=SkillCheckResult.DENY.value,
                    reason=reason,
                    skill_name=skill_identifier,
                    action=f"{operation_type}: {operation_detail}",
                )
        
        # DefaultAllow
        return SkillCheckResponse(
            result=SkillCheckResult.ALLOW.value,
            reason="OperationDangerous",
            skill_name=skill_identifier,
            action=f"{operation_type}: {operation_detail}",
        )
    
    def add_trusted_skill(self, skill_identifier: str):
        """Trusted Skill"""
        if skill_identifier not in self.trusted_skills:
            self.trusted_skills.append(skill_identifier)
            
            if "*" in skill_identifier:
                pattern = skill_identifier.replace("*", ".*")
                self._trusted_patterns.append(re.compile(f"^{pattern}$"))
    
    def remove_trusted_skill(self, skill_identifier: str):
        """Trusted Skill"""
        if skill_identifier in self.trusted_skills:
            self.trusted_skills.remove(skill_identifier)
    
    def get_trusted_skills(self) -> List[str]:
        """Trusted Skill List"""
        return self.trusted_skills.copy()
    
    @classmethod
    def from_config(cls, config_path: str) -> "SkillChecker":
        """Create instance from config file"""
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        skill_rules = config.get("skill_rules", {})
        
        return cls(
            trusted_skills=skill_rules.get("trusted_skills", []),
            untrusted_actions=skill_rules.get("untrusted_actions", []),
        )


# Convenience function
def skill_check(
    identifier: str,
    name: Optional[str] = None,
) -> SkillCheckResponse:
    """
     Skill 
    
    Args:
        identifier: Skill 
        name: Skill （）
        
    Returns:
        SkillCheckResponse: Result
    """
    checker = SkillChecker()
    return checker.check_skill(identifier, name)