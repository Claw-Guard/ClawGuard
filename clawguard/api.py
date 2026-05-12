"""
ClawGuard API Server
FastAPI service providing REST API and SSE endpoints
"""

import os
import asyncio
from typing import Optional, Dict, Any
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .sanitizer import Sanitizer
from .rules import RuleEngine, ActionType
from .audit import AuditLogger, AuditAction, AuditResult
from .approval import ApprovalQueue, ApprovalType, ApprovalStatus, ApprovalRequest
from .panic import PanicManager, PanicTrigger


# ================================
# Pydantic Models
# ================================

class CommandRequest(BaseModel):
    command: str
    session_id: Optional[str] = ""
    agent_id: Optional[str] = ""


class FileRequest(BaseModel):
    path: str
    operation: str  # "read" or "write"
    content: Optional[str] = ""
    session_id: Optional[str] = ""
    agent_id: Optional[str] = ""


class NetworkRequest(BaseModel):
    url: str
    method: Optional[str] = "GET"
    session_id: Optional[str] = ""
    agent_id: Optional[str] = ""


class SanitizeRequest(BaseModel):
    text: str
    skill_name: Optional[str] = None
    direction: Optional[str] = "output"  # "input" or "output"


class SkillCheckRequest(BaseModel):
    identifier: str
    name: Optional[str] = None
    action: Optional[str] = None


class ApprovalActionRequest(BaseModel):
    request_id: str
    resolved_by: str
    reason: Optional[str] = ""


class PanicRequest(BaseModel):
    reason: Optional[str] = ""
    trigger: Optional[str] = "api"
    triggered_by: Optional[str] = "api_user"


class ResumeRequest(BaseModel):
    resolved_by: str
    reason: Optional[str] = ""


class ToolCallRequest(BaseModel):
    tool: str
    input: Dict[str, Any]
    session_id: Optional[str] = ""
    agent_id: Optional[str] = ""


# ================================
# ClawGuard API App
# ================================

def create_app(
    config_path: Optional[str] = None,
    rules_path: Optional[str] = None,
) -> FastAPI:
    """
    Create FastAPI application
    
    Args:
        config_path: Configuration file path
        rules_path: Rules file path
        
    Returns:
        FastAPI application instance
    """
    app = FastAPI(
        title="ClawGuard API",
        description="ClawGuard: Runtime Security Framework for Tool-Augmented LLM Agents",
        version="1.0.0",
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Load configuration
    config = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    
    rules_config = {}
    if rules_path and os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_config = yaml.safe_load(f)
    
    # Initialize components
    app.state.sanitizer = Sanitizer(
        patterns=rules_config.get("sanitizer_rules", {}).get("patterns"),
        skill_whitelist=rules_config.get("sanitizer_rules", {}).get("skill_whitelist", []),
    )
    app.state.rules = RuleEngine(rules_config)
    app.state.audit = AuditLogger(
        db_path=config.get("audit", {}).get("db_path", "~/.clawguard/audit.db"),
    )
    app.state.approval = ApprovalQueue(
        timeout_seconds=config.get("policy", {}).get("approval_timeout", 60),
    )
    app.state.timeout_action = config.get("policy", {}).get("timeout_action", "deny")
    app.state.panic = PanicManager()
    
    # Set up approval resolution callback to log to audit
    async def on_approval_resolution(request: ApprovalRequest):
        """Log approval decisions to audit trail"""
        if request.status == ApprovalStatus.APPROVED.value:
            app.state.audit.log(
                action=AuditAction.APPROVAL_APPROVE,
                result=AuditResult.APPROVED,
                operation=request.operation,
                reason=request.resolution_reason or "Approved by user",
                details={"approval_type": request.approval_type, "resolved_by": request.resolved_by},
            )
        elif request.status == ApprovalStatus.DENIED.value:
            app.state.audit.log(
                action=AuditAction.APPROVAL_DENY,
                result=AuditResult.DENIED,
                operation=request.operation,
                reason=request.resolution_reason or "Denied by user",
                details={"approval_type": request.approval_type, "resolved_by": request.resolved_by},
            )
    
    app.state.approval.set_on_resolution(on_approval_resolution)
    
    # Dashboard directory
    dashboard_dir = Path(__file__).parent / "dashboard"
    
    # ================================
    # Routes: Dashboard
    # ================================
    
    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve dashboard HTML"""
        # Try enhanced version first
        enhanced_path = dashboard_dir / "index-enhanced.html"
        if enhanced_path.exists():
            return HTMLResponse(content=enhanced_path.read_text())
        
        # Fallback to original
        index_path = dashboard_dir / "index.html"
        if index_path.exists():
            return HTMLResponse(content=index_path.read_text())
        return HTMLResponse(content="<h1>Dashboard not found</h1>")
    
    @app.get("/static/css/style.css")
    async def dashboard_css():
        """Serve dashboard CSS"""
        css_path = dashboard_dir / "style.css"
        if css_path.exists():
            return FileResponse(css_path, media_type="text/css")
        return HTMLResponse(content="/* CSS not found */", status_code=404)
    
    @app.get("/static/js/app.js")
    async def dashboard_js():
        """Serve dashboard JavaScript (original)"""
        js_path = dashboard_dir / "app.js"
        if js_path.exists():
            return FileResponse(js_path, media_type="application/javascript")
        return HTMLResponse(content="// JS not found", status_code=404)
    
    @app.get("/static/js/app-enhanced.js")
    async def dashboard_js_enhanced():
        """Serve enhanced dashboard JavaScript"""
        js_path = dashboard_dir / "app-enhanced.js"
        if js_path.exists():
            return FileResponse(js_path, media_type="application/javascript")
        return HTMLResponse(content="// Enhanced JS not found", status_code=404)
    
    # ================================
    # Routes: Status
    # ================================
    
    @app.get("/api")
    async def api_root():
        """API root endpoint"""
        return {
            "name": "ClawGuard",
            "version": "1.0.0",
            "status": "running",
            "panic_state": app.state.panic.state.value,
        }
    
    @app.get("/status")
    async def status():
        """Get full status"""
        return {
            "panic": app.state.panic.get_status(),
            "approval": app.state.approval.get_stats(),
            "audit": app.state.audit.get_stats(hours=24),
            "task_scope": {
                "active": app.state.rules.task_scope_active,
                "locked": getattr(app.state.rules, "task_scope_locked", False),
                "rules": app.state.rules.task_scope_rules,
            },
        }
    
    @app.get("/api/status")
    async def api_status():
        """Get API status for OpenClaw plugin"""
        stats = app.state.audit.get_stats(hours=24)
        return {
            "version": "1.0.0",
            "mode": config.get("policy", {}).get("mode", "permissive"),
            "panic": app.state.panic.is_panicking,
            "pid": os.getpid(),
            "audit_total": stats.get("total_operations", 0),
            "audit_denied": stats.get("denied_count", 0),
        }
    
    # ================================
    # Routes: Sanitizer
    # ================================
    
    @app.post("/api/tool/call")
    async def tool_call(request: ToolCallRequest):
        """Handle tool calls from OpenClaw plugin"""
        # Check panic first
        if app.state.panic.is_panicking:
            return {"error": "ClawGuard is in Panic mode"}
        
        tool = request.tool
        params = request.input
        
        # Check if tool is disabled by active task scope
        if app.state.rules.is_tool_disabled(tool):
            app.state.audit.log(
                action=AuditAction.RULE_DENY,
                result=AuditResult.DENIED,
                operation=f"tool:{tool}",
                reason=f"Tool '{tool}' disabled by active task scope",
                session_id=request.session_id,
                agent_id=request.agent_id,
            )
            return {"error": f"Tool '{tool}' is disabled by the current task scope"}
        
        try:
            if tool == "execute_command":
                command = params.get("command", "")
                result = app.state.rules.check_command(command)

                if result.action == ActionType.DENY:
                    app.state.audit.log_command(command, AuditResult.DENIED, result.reason, request.session_id, request.agent_id)
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.COMMAND,
                        operation=command,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass  # timeout → allow
                        else:
                            return {"error": f"Command not permitted: {final.status} — {final.resolution_reason or result.reason}"}
                    # Approved or timeout-allow — fall through to execute

                # ALLOW or just-approved: execute the command
                sanitized_command = app.state.sanitizer.sanitize_input(command)
                proc = await asyncio.create_subprocess_shell(
                    sanitized_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                raw_output = stdout.decode() + stderr.decode()
                sanitized_output = app.state.sanitizer.sanitize_output(raw_output)
                app.state.audit.log_command(
                    sanitized_command, AuditResult.ALLOWED, result.reason,
                    request.session_id, request.agent_id
                )
                return {"result": sanitized_output}
            
            elif tool == "read_file":
                path = params.get("path", "")
                offset = params.get("offset", 0)
                limit = params.get("limit", None)

                import datetime, json as _json
                _log_path = os.path.expanduser("~/.clawguard/read_debug.log")
                def _rlog(stage, **kw):
                    entry = {"ts": datetime.datetime.now().isoformat(), "stage": stage, "path": path, **kw}
                    with open(_log_path, "a") as _lf:
                        _lf.write(_json.dumps(entry) + "\n")

                _rlog("received", offset=offset, limit=limit,
                      task_scope_active=app.state.rules.task_scope_active,
                      task_scope_rules=app.state.rules.task_scope_rules)

                result = app.state.rules.check_file_path(path, "read")
                _rlog("rule_check", action=str(result.action), reason=result.reason)

                if result.action == ActionType.DENY:
                    app.state.audit.log_file_access(path, "read", AuditResult.DENIED, result.reason, request.session_id, request.agent_id)
                    _rlog("denied")
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.FILE_READ_SENSITIVE,
                        operation=path,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass
                        else:
                            _rlog("approval_denied", status=final.status)
                            return {"error": f"File read not permitted: {final.status} — {final.resolution_reason or result.reason}"}

                # ALLOW or just-approved: read the file
                expanded = os.path.expanduser(path)
                file_exists = os.path.exists(expanded)
                file_size = os.path.getsize(expanded) if file_exists else -1
                _rlog("pre_read", expanded=expanded, exists=file_exists, size_bytes=file_size)

                with open(expanded, 'r') as f:
                    if offset > 1:
                        for _ in range(offset - 1):
                            f.readline()
                    if limit:
                        content = ''.join([f.readline() for _ in range(limit)])
                    else:
                        content = f.read()

                _rlog("post_read", content_len=len(content), content_preview=repr(content[:80]))

                sanitized_content = app.state.sanitizer.sanitize_output(content)
                _rlog("post_sanitize", sanitized_len=len(sanitized_content), sanitized_preview=repr(sanitized_content[:80]))

                app.state.audit.log_file_access(
                    path, "read", AuditResult.ALLOWED, result.reason,
                    request.session_id, request.agent_id
                )
                _rlog("returning", result_len=len(sanitized_content))
                return {"result": sanitized_content}
            
            elif tool == "write_file":
                path = params.get("path", "")
                content = params.get("content", "")

                result = app.state.rules.check_file_path(path, "write")

                if result.action == ActionType.DENY:
                    app.state.audit.log_file_access(path, "write", AuditResult.DENIED, result.reason, request.session_id, request.agent_id)
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.FILE_WRITE,
                        operation=path,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass  # timeout → allow
                        else:
                            return {"error": f"File write not permitted: {final.status} — {final.resolution_reason or result.reason}"}
                    # Approved or timeout-allow — fall through to write

                # ALLOW or just-approved: write the file
                expanded_path = os.path.expanduser(path)
                os.makedirs(os.path.dirname(expanded_path), exist_ok=True)
                with open(expanded_path, 'w') as f:
                    f.write(content)
                app.state.audit.log_file_access(path, "write", AuditResult.ALLOWED, result.reason, request.session_id, request.agent_id)
                return {"result": f"File written: {path}"}
            
            elif tool == "list_directory":
                path = params.get("path", ".")

                result = app.state.rules.check_file_path(path, "read")

                if result.action == ActionType.DENY:
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.FILE_READ_SENSITIVE,
                        operation=path,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass  # timeout → allow
                        else:
                            return {"error": f"Directory listing not permitted: {final.status} — {final.resolution_reason or result.reason}"}
                    # Approved or timeout-allow — fall through to list

                # ALLOW or just-approved: list the directory
                expanded_path = os.path.expanduser(path)
                entries = os.listdir(expanded_path)
                listing = "\n".join(entries)
                return {"result": listing}
            
            elif tool == "http_request":
                url = params.get("url", "")
                method = params.get("method", "GET")
                extract_mode = params.get("extract_mode", "markdown")
                max_chars = params.get("max_chars", None)
                headers = params.get("headers", {})
                body = params.get("body", None)

                result = app.state.rules.check_network(url)

                if result.action == ActionType.DENY:
                    app.state.audit.log_network(url, AuditResult.DENIED, result.reason, request.session_id, request.agent_id)
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.NETWORK,
                        operation=url,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass  # timeout → allow
                        else:
                            return {"error": f"Network request not permitted: {final.status} — {final.resolution_reason or result.reason}"}
                    # Approved or timeout-allow — fall through to request

                # ALLOW or just-approved: make the HTTP request
                import httpx
                async with httpx.AsyncClient(follow_redirects=True) as client:
                    response = await client.request(method, url, headers=headers, content=body)
                    
                    # Extract content based on mode
                    content_type = response.headers.get("content-type", "").lower()
                    raw_body = response.text
                    
                    # HTML→Markdown conversion
                    if extract_mode == "markdown" and "html" in content_type:
                        try:
                            from html2text import HTML2Text
                            h = HTML2Text()
                            h.ignore_links = False
                            h.ignore_images = False
                            h.ignore_emphasis = False
                            h.body_width = 0  # No wrapping
                            extracted = h.handle(raw_body)
                        except ImportError:
                            # Fallback: strip HTML tags if html2text not available
                            import re
                            extracted = re.sub(r'<[^>]+>', '', raw_body)
                    elif extract_mode == "text":
                        # Strip all HTML tags
                        import re
                        extracted = re.sub(r'<[^>]+>', '', raw_body)
                    else:
                        # raw mode
                        extracted = raw_body
                    
                    # Truncate if max_chars specified
                    if max_chars and len(extracted) > max_chars:
                        extracted = extracted[:max_chars] + "\n\n[... truncated ...]"
                    
                    # Sanitize output
                    sanitized_body = app.state.sanitizer.sanitize_output(extracted)
                    
                    app.state.audit.log_network(
                        url, AuditResult.ALLOWED, result.reason,
                        request.session_id, request.agent_id
                    )
                    return {"result": sanitized_body}
            
            elif tool == "skill_check":
                identifier = params.get("identifier", "")
                from .skill_check import SkillChecker
                checker = SkillChecker()
                result = checker.check_skill(identifier)
                return {"result": result.to_dict().get("message", "Check complete")}
            
            elif tool == "set_task_scope":
                task_description = params.get("task_description", "")
                file_read = params.get("file_read", [])
                file_write = params.get("file_write", [])
                commands = params.get("commands", [])
                network = params.get("network", [])
                disabled_tools = params.get("disable_tools", params.get("disabled_tools", []))
                
                scope_result = app.state.rules.set_task_scope(
                    task_description=task_description,
                    file_read=file_read,
                    file_write=file_write,
                    commands=commands,
                    network=network,
                    disabled_tools=disabled_tools,
                )
                
                if scope_result.get("error"):
                    app.state.audit.log(
                        action=AuditAction.RULE_DENY,
                        result=AuditResult.DENIED,
                        operation=f"set_task_scope: {task_description}",
                        reason=scope_result["error"],
                        details={
                            "file_read": file_read,
                            "file_write": file_write,
                            "commands": commands,
                            "network": network,
                            "disabled_tools": disabled_tools,
                        },
                        session_id=request.session_id,
                        agent_id=request.agent_id,
                    )
                    return {"error": scope_result["error"]}
                
                # Log to audit
                app.state.audit.log(
                    action=AuditAction.RULE_DENY,  # Using RULE_DENY as category for scope operations
                    result=AuditResult.ALLOWED,
                    operation=f"set_task_scope: {task_description}",
                    reason="Task scope applied — rules injected into rule engine",
                    details={
                        "file_read": file_read,
                        "file_write": file_write,
                        "commands": commands,
                        "network": network,
                        "disabled_tools": disabled_tools,
                    },
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                )
                
                return {"result": f"✅ Task scope set: {task_description}"}
            
            elif tool == "clear_task_scope":
                scope_result = app.state.rules.clear_task_scope()
                
                # Log to audit
                app.state.audit.log(
                    action=AuditAction.RULE_DENY,
                    result=AuditResult.ALLOWED,
                    operation="clear_task_scope",
                    reason="Task scope cleared — injected rules removed from rule engine",
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                )
                
                return {"result": "✅ Task scope cleared"}
            
            elif tool == "edit_file":
                path = params.get("path", "")
                edits = params.get("edits", [])
                
                # Check file access permission
                result = app.state.rules.check_file_path(path, "write")
                
                if result.action == ActionType.DENY:
                    app.state.audit.log_file_access(path, "write", AuditResult.DENIED, result.reason, request.session_id, request.agent_id)
                    return {"error": result.reason}
                elif result.action == ActionType.APPROVE:
                    approval_req = await app.state.approval.add_request(
                        approval_type=ApprovalType.FILE_WRITE,
                        operation=path,
                        reason=result.reason,
                    )
                    final = await app.state.approval.wait_for_decision(approval_req.id)
                    if final.status != ApprovalStatus.APPROVED.value:
                        if final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                            pass  # timeout → allow
                        else:
                            return {"error": f"File edit not permitted: {final.status} — {final.resolution_reason or result.reason}"}
                
                # Read current file content
                expanded_path = os.path.expanduser(path)
                try:
                    with open(expanded_path, 'r') as f:
                        content = f.read()
                except FileNotFoundError:
                    return {"error": f"File not found: {path}"}
                
                # Apply edits
                modified_content = content
                for edit in edits:
                    old_text = edit.get("oldText", "")
                    new_text = edit.get("newText", "")
                    
                    # Check that oldText appears exactly once
                    count = modified_content.count(old_text)
                    if count == 0:
                        return {"error": f"oldText not found in file: {old_text[:50]}..."}
                    elif count > 1:
                        return {"error": f"oldText appears {count} times (must be unique): {old_text[:50]}..."}
                    
                    # Apply replacement
                    modified_content = modified_content.replace(old_text, new_text, 1)
                
                # Write back
                with open(expanded_path, 'w') as f:
                    f.write(modified_content)
                
                app.state.audit.log_file_access(path, "write", AuditResult.ALLOWED, result.reason, request.session_id, request.agent_id)
                return {"result": f"✅ Edits applied: {path}"}
            
            else:
                return {"error": f"Unknown tool: {tool}"}
        
        except Exception as e:
            return {"error": str(e)}
    
    # ================================
    # Routes: Sanitizer
    # ================================
    
    @app.post("/sanitize")
    async def sanitize(request: SanitizeRequest):
        """Sanitize text"""
        if request.direction == "input":
            result = app.state.sanitizer.sanitize_input(request.text, request.skill_name)
        else:
            result = app.state.sanitizer.sanitize_output(request.text, request.skill_name)
        
        return {
            "original_length": len(request.text),
            "sanitized": result,
            "sanitized_length": len(result),
        }
    
    @app.post("/detect-secrets")
    async def detect_secrets(request: SanitizeRequest):
        """Detect sensitive information"""
        detected = app.state.sanitizer.detect_secrets(request.text)
        return {
            "count": len(detected),
            "secrets": detected,
        }
    
    # ================================
    # Routes: Rule Engine
    # ================================
    
    @app.post("/check/command")
    async def check_command(request: CommandRequest):
        """Check if command complies with rules"""
        # Panic check
        if app.state.panic.is_panicking:
            return JSONResponse(
                status_code=403,
                content={
                    "allowed": False,
                    "reason": "ClawGuard is in Panic mode",
                }
            )
        
        result = app.state.rules.check_command(request.command)
        
        # Log audit
        audit_result = AuditResult.ALLOWED if result.action == ActionType.ALLOW else AuditResult.DENIED
        app.state.audit.log_command(
            command=request.command,
            result=audit_result,
            reason=result.reason,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )
        
        response = {
            "allowed": result.action == ActionType.ALLOW,
            "action": result.action.value,
            "reason": result.reason,
            "pattern": result.pattern,
        }
        
        # Needs approval — block until human decides or timeout
        if result.action == ActionType.APPROVE:
            approval_req = await app.state.approval.add_request(
                approval_type=ApprovalType.COMMAND,
                operation=request.command,
                reason=result.reason,
                details={"pattern": result.pattern},
            )
            final = await app.state.approval.wait_for_decision(approval_req.id)
            if final.status == ApprovalStatus.APPROVED.value:
                return {"allowed": True, "action": "allow", "reason": "Approved by human", "pattern": result.pattern}
            else:
                return {"allowed": False, "action": "deny", "reason": f"Not approved: {final.status} — {final.resolution_reason or result.reason}", "pattern": result.pattern}
        
        return response
    
    @app.post("/check/file")
    async def check_file(request: FileRequest):
        """Check file path access permission"""
        if app.state.panic.is_panicking:
            return JSONResponse(
                status_code=403,
                content={
                    "allowed": False,
                    "reason": "ClawGuard is in Panic mode",
                }
            )
        
        result = app.state.rules.check_file_path(request.path, request.operation)
        
        # Log audit
        audit_result = AuditResult.ALLOWED if result.action == ActionType.ALLOW else AuditResult.DENIED
        app.state.audit.log_file_access(
            path=request.path,
            operation=request.operation,
            result=audit_result,
            reason=result.reason,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )
        
        response = {
            "allowed": result.action == ActionType.ALLOW,
            "action": result.action.value,
            "reason": result.reason,
        }
        
        if result.action == ActionType.APPROVE:
            approval_req = await app.state.approval.add_request(
                approval_type=ApprovalType.FILE_WRITE if request.operation == "write" else ApprovalType.FILE_READ_SENSITIVE,
                operation=request.path,
                reason=result.reason,
            )
            final = await app.state.approval.wait_for_decision(approval_req.id)
            if final.status == ApprovalStatus.APPROVED.value:
                return {"allowed": True, "action": "allow", "reason": "Approved by human"}
            elif final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                return {"allowed": True, "action": "allow", "reason": "Timeout → allowed by policy"}
            else:
                return {"allowed": False, "action": "deny", "reason": f"Not approved: {final.status} — {final.resolution_reason or result.reason}"}
        
        return response
    
    @app.post("/check/network")
    async def check_network(request: NetworkRequest):
        """Check if network request complies with rules"""
        if app.state.panic.is_panicking:
            return JSONResponse(
                status_code=403,
                content={
                    "allowed": False,
                    "reason": "ClawGuard is in Panic mode",
                }
            )
        
        result = app.state.rules.check_network(request.url)
        
        audit_result = AuditResult.ALLOWED if result.action == ActionType.ALLOW else AuditResult.DENIED
        app.state.audit.log_network(
            url=request.url,
            result=audit_result,
            reason=result.reason,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )
        
        response = {
            "allowed": result.action == ActionType.ALLOW,
            "action": result.action.value,
            "reason": result.reason,
        }
        
        if result.action == ActionType.APPROVE:
            approval_req = await app.state.approval.add_request(
                approval_type=ApprovalType.NETWORK,
                operation=request.url,
                reason=result.reason,
            )
            final = await app.state.approval.wait_for_decision(approval_req.id)
            if final.status == ApprovalStatus.APPROVED.value:
                return {"allowed": True, "action": "allow", "reason": "Approved by human"}
            elif final.status == ApprovalStatus.TIMEOUT.value and app.state.timeout_action == "allow":
                return {"allowed": True, "action": "allow", "reason": "Timeout → allowed by policy"}
            else:
                return {"allowed": False, "action": "deny", "reason": f"Not approved: {final.status} — {final.resolution_reason or result.reason}"}
        
        return response
    
    # ================================
    # Routes: Approval Queue
    # ================================
    
    @app.get("/approval/pending")
    async def get_pending_approvals():
        """Get pending approval list"""
        return {
            "count": len(app.state.approval.get_pending()),
            "requests": [r.to_dict() for r in app.state.approval.get_pending()],
        }
    
    @app.post("/approval/approve")
    async def approve_request(request: ApprovalActionRequest):
        """Approve request"""
        result = await app.state.approval.approve(
            request_id=request.request_id,
            resolved_by=request.resolved_by,
            reason=request.reason,
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        
        return {"status": "approved", "request": result.to_dict()}
    
    @app.post("/approval/deny")
    async def deny_request(request: ApprovalActionRequest):
        """Deny request"""
        result = await app.state.approval.deny(
            request_id=request.request_id,
            resolved_by=request.resolved_by,
            reason=request.reason,
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        
        return {"status": "denied", "request": result.to_dict()}
    
    @app.get("/approval/history")
    async def get_approval_history(limit: int = Query(50, ge=1, le=200)):
        """Get approval history"""
        return {
            "history": [r.to_dict() for r in app.state.approval.get_history(limit)],
        }
    
    @app.get("/approval/sse")
    async def approval_sse():
        """SSE realtime push for approval events"""
        return EventSourceResponse(app.state.approval.sse_stream())
    
    # ================================
    # Routes: Panic / Resume
    # ================================
    
    @app.get("/panic/status")
    async def get_panic_status():
        """Get Panic status"""
        return app.state.panic.get_status()
    
    @app.post("/panic")
    async def trigger_panic(request: PanicRequest):
        """Trigger Panic"""
        trigger = PanicTrigger(request.trigger)
        record = await app.state.panic.panic(
            trigger=trigger,
            reason=request.reason,
            triggered_by=request.triggered_by,
        )
        return {"status": "panic", "record": record.__dict__}
    
    @app.post("/resume")
    async def trigger_resume(request: ResumeRequest):
        """Resume operation"""
        record = await app.state.panic.resume(
            resolved_by=request.resolved_by,
            reason=request.reason,
        )
        if not record:
            return {"status": "already_normal", "message": "Not in panic state"}
        return {"status": "resumed", "record": record.__dict__}
    
    @app.get("/panic/sse")
    async def panic_sse():
        """SSE realtime push for Panic status"""
        return EventSourceResponse(app.state.panic.sse_stream())
    
    # ================================
    # Routes: Skill Check
    # ================================
    
    @app.post("/skill/check")
    async def check_skill(request: SkillCheckRequest):
        """Check if Skill is compliant"""
        from .skill_check import SkillChecker
        checker = SkillChecker()
        result = checker.check_skill(request.identifier, request.name, request.action)
        return result.to_dict()
    
    # ================================
    # Routes: Audit
    # ================================
    
    @app.get("/audit/stats")
    async def get_audit_stats(hours: int = Query(24, ge=1, le=168)):
        """Get audit statistics"""
        return app.state.audit.get_stats(hours)
    
    @app.get("/audit/logs")
    async def get_audit_logs(
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        action: Optional[str] = None,
        result: Optional[str] = None,
    ):
        """Get audit logs"""
        logs = app.state.audit.query(
            action=action,
            result=result,
            limit=limit,
            offset=offset,
        )
        return {
            "count": len(logs),
            "logs": [l.to_dict() for l in logs],
        }
    
    @app.get("/audit/download")
    async def download_audit_logs(
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        Download audit logs as JSON file
        
        Query Parameters:
        - start_time: Unix timestamp (optional, filter logs after this time)
        - end_time: Unix timestamp (optional, filter logs before this time)
        - action: Filter by action type (optional)
        - result: Filter by result (optional)
        - session_id: Filter by session ID (optional)
        
        Returns:
        JSON file with filtered audit logs
        """
        from datetime import datetime
        from fastapi.responses import Response
        import json
        
        # Query all matching logs (no limit for download)
        logs = app.state.audit.query(
            action=action,
            result=result,
            session_id=session_id,
            start_time=start_time,
            end_time=end_time,
            limit=100000,  # High limit for export
            offset=0,
        )
        
        # Convert to dict format
        log_data = {
            "export_metadata": {
                "exported_at": datetime.now().isoformat(),
                "total_records": len(logs),
                "filters": {
                    "start_time": start_time,
                    "end_time": end_time,
                    "action": action,
                    "result": result,
                    "session_id": session_id,
                },
            },
            "logs": [l.to_dict() for l in logs],
        }
        
        # Generate filename with timestamp
        filename = f"clawguard_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Return as downloadable JSON
        json_content = json.dumps(log_data, ensure_ascii=False, indent=2)
        
        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
    
    # ================================
    # Routes: Dynamic Rule Management
    # ================================
    
    @app.post("/rules/network/allow")
    async def add_allowed_domain(domain: str):
        """Add domain to network whitelist"""
        if domain not in app.state.rules.network_rules["allowed_domains"]:
            app.state.rules.network_rules["allowed_domains"].append(domain)
            return {"status": "added", "domain": domain}
        return {"status": "already_exists", "domain": domain}
    
    @app.post("/rules/network/deny")
    async def add_denied_domain(domain: str):
        """Add domain to network blacklist"""
        if domain not in app.state.rules.network_rules["denied_domains"]:
            app.state.rules.network_rules["denied_domains"].append(domain)
            return {"status": "added", "domain": domain}
        return {"status": "already_exists", "domain": domain}
    
    @app.post("/rules/file/allow")
    async def add_allowed_path(path: str):
        """Add path to file whitelist"""
        expanded = os.path.expanduser(path)
        if expanded not in app.state.rules.file_rules["allowed_paths"]:
            app.state.rules.file_rules["allowed_paths"].append(expanded)
            return {"status": "added", "path": expanded}
        return {"status": "already_exists", "path": expanded}
    
    @app.post("/rules/file/deny")
    async def add_denied_path(path: str):
        """Add path to file blacklist"""
        expanded = os.path.expanduser(path)
        if expanded not in app.state.rules.file_rules["denied_paths"]:
            app.state.rules.file_rules["denied_paths"].append(expanded)
            return {"status": "added", "path": expanded}
        return {"status": "already_exists", "path": expanded}
    
    @app.delete("/rules/network/allow/{domain}")
    async def remove_allowed_domain(domain: str):
        """Remove domain from network whitelist"""
        if domain in app.state.rules.network_rules["allowed_domains"]:
            app.state.rules.network_rules["allowed_domains"].remove(domain)
            return {"status": "removed", "domain": domain}
        return {"status": "not_found", "domain": domain}
    
    @app.delete("/rules/network/deny/{domain}")
    async def remove_denied_domain(domain: str):
        """Remove domain from network blacklist"""
        if domain in app.state.rules.network_rules["denied_domains"]:
            app.state.rules.network_rules["denied_domains"].remove(domain)
            return {"status": "removed", "domain": domain}
        return {"status": "not_found", "domain": domain}
    
    @app.delete("/rules/file/allow")
    async def remove_allowed_path(path: str):
        """Remove path from file whitelist"""
        expanded = os.path.expanduser(path)
        if expanded in app.state.rules.file_rules["allowed_paths"]:
            app.state.rules.file_rules["allowed_paths"].remove(expanded)
            return {"status": "removed", "path": expanded}
        return {"status": "not_found", "path": expanded}
    
    @app.delete("/rules/file/deny")
    async def remove_denied_path(path: str):
        """Remove path from file blacklist"""
        expanded = os.path.expanduser(path)
        if expanded in app.state.rules.file_rules["denied_paths"]:
            app.state.rules.file_rules["denied_paths"].remove(expanded)
            return {"status": "removed", "path": expanded}
        return {"status": "not_found", "path": expanded}
    
    @app.get("/rules/list")
    async def list_rules():
        """Get current runtime rules including task scope"""
        return {
            "network": {
                "allowed_domains": app.state.rules.network_rules["allowed_domains"],
                "denied_domains": app.state.rules.network_rules["denied_domains"],
            },
            "file": {
                "allowed_paths": app.state.rules.file_rules["allowed_paths"],
                "denied_paths": app.state.rules.file_rules["denied_paths"],
            },
            "task_scope": {
                "active": app.state.rules.task_scope_active,
                "locked": getattr(app.state.rules, "task_scope_locked", False),
                "rules": app.state.rules.task_scope_rules,
            },
        }
    
    @app.post("/task-scope/lock")
    async def lock_task_scope():
        return app.state.rules.lock_task_scope()
    
    @app.post("/task-scope/unlock")
    async def unlock_task_scope():
        return app.state.rules.unlock_task_scope()
    
    @app.post("/task-scope/clear")
    async def clear_task_scope_route():
        return app.state.rules.clear_task_scope()

    return app


# Default application
app = create_app(
    config_path=os.path.expanduser("~/.clawguard/config.yaml"),
    rules_path=os.path.expanduser("~/.clawguard/rules.yaml"),
)