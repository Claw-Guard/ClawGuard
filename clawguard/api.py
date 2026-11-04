"""
ClawGuard API Server
FastAPI service providing REST API and SSE endpoints
"""

import os
import asyncio
import json
import re
import stat
import tempfile
import threading
from typing import Optional, Dict, Any, Mapping
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
from .adapters import agent_adapters


# ================================
# Pydantic Models
# ================================

class CommandRequest(BaseModel):
    command: str
    cwd: Optional[str] = ""
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
    settings: Optional[Any] = None,
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

    app.state.rules_path = (
        os.path.abspath(os.path.expanduser(rules_path)) if rules_path else None
    )
    app.state.rules_write_lock = threading.Lock()

    def persist_rule_change(
        section: str,
        key: str,
        value: str,
        *,
        add: bool,
    ) -> bool:
        """Update one rule-list entry in rules.yaml atomically.

        The edit is intentionally line-oriented so comments and unrelated
        policy formatting are preserved.  The resulting document is parsed
        before the atomic replace, and memory is updated by the caller only
        after this function succeeds.
        """
        path = app.state.rules_path
        if not path:
            raise HTTPException(
                status_code=500,
                detail="Rules persistence is unavailable: rules_path is not configured",
            )

        def comparable(item: Any) -> str:
            text = str(item)
            return os.path.expanduser(text) if section == "file_rules" else text

        with app.state.rules_write_lock:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    original = handle.read()
                lines = original.splitlines(keepends=True)
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unable to read rules file: {exc}",
                ) from exc

            section_index = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if line.rstrip() == f"{section}:"
                ),
                None,
            )
            if section_index is None:
                raise HTTPException(
                    status_code=500,
                    detail=f"Rules file has no {section} section",
                )

            section_end = len(lines)
            for index in range(section_index + 1, len(lines)):
                line = lines[index]
                if (
                    line.strip()
                    and not line.lstrip().startswith("#")
                    and len(line) - len(line.lstrip()) == 0
                ):
                    section_end = index
                    break

            key_index = next(
                (
                    index
                    for index in range(section_index + 1, section_end)
                    if lines[index].rstrip() == f"  {key}:"
                ),
                None,
            )
            if key_index is None:
                raise HTTPException(
                    status_code=500,
                    detail=f"Rules file has no {section}.{key} list",
                )

            key_end = section_end
            for index in range(key_index + 1, section_end):
                line = lines[index]
                if (
                    line.strip()
                    and not line.lstrip().startswith("#")
                    and len(line) - len(line.lstrip()) <= 2
                ):
                    key_end = index
                    break

            matching_index = None
            for index in range(key_index + 1, key_end):
                stripped = lines[index].strip()
                if not stripped.startswith("- "):
                    continue
                try:
                    item = yaml.safe_load(stripped[2:].strip())
                except yaml.YAMLError:
                    continue
                if comparable(item) == value:
                    matching_index = index
                    break

            if add and matching_index is None:
                rendered = json.dumps(value, ensure_ascii=False)
                lines.insert(key_index + 1, f"    - {rendered}\n")
            elif not add and matching_index is not None:
                lines.pop(matching_index)
            else:
                return False

            updated = "".join(lines)
            try:
                parsed = yaml.safe_load(updated)
                persisted_values = parsed[section][key]
                if not isinstance(persisted_values, list):
                    raise ValueError(f"{section}.{key} is not a list")
            except (KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Refusing to persist invalid rules YAML: {exc}",
                ) from exc

            mode = stat.S_IMODE(os.stat(path).st_mode)
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    newline="",
                    dir=os.path.dirname(path),
                    prefix=".rules.",
                    suffix=".tmp",
                    delete=False,
                ) as handle:
                    temp_path = handle.name
                    handle.write(updated)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_path, mode)
                os.replace(temp_path, path)
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unable to persist rules file: {exc}",
                ) from exc
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
            return True

    def persist_command_rule_change(
        category: str,
        pattern: str,
        reason: str,
        *,
        add: bool,
    ) -> bool:
        """Add or remove one command rule while preserving YAML comments."""
        path = app.state.rules_path
        if not path:
            raise HTTPException(
                status_code=500,
                detail="Rules persistence is unavailable: rules_path is not configured",
            )

        with app.state.rules_write_lock:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    original = handle.read()
                lines = original.splitlines(keepends=True)
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unable to read rules file: {exc}",
                ) from exc

            section_index = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if line.rstrip() == "command_rules:"
                ),
                None,
            )
            if section_index is None:
                raise HTTPException(
                    status_code=500,
                    detail="Rules file has no command_rules section",
                )

            section_end = len(lines)
            for index in range(section_index + 1, len(lines)):
                line = lines[index]
                if (
                    line.strip()
                    and not line.lstrip().startswith("#")
                    and len(line) - len(line.lstrip()) == 0
                ):
                    section_end = index
                    break

            key_pattern = re.compile(
                rf"^  {re.escape(category)}:\s*(.*?)\s*$"
            )
            key_match = None
            key_index = None
            for index in range(section_index + 1, section_end):
                candidate = key_pattern.match(lines[index].rstrip("\r\n"))
                if candidate:
                    key_match = candidate
                    key_index = index
                    break
            if key_index is None:
                raise HTTPException(
                    status_code=500,
                    detail=f"Rules file has no command_rules.{category} list",
                )

            key_end = section_end
            for index in range(key_index + 1, section_end):
                line = lines[index]
                if (
                    line.strip()
                    and not line.lstrip().startswith("#")
                    and len(line) - len(line.lstrip()) <= 2
                ):
                    key_end = index
                    break

            matching_index = None
            for index in range(key_index + 1, key_end):
                match = re.match(
                    r"^\s{4}-\s+pattern:\s*(.*?)\s*$",
                    lines[index],
                )
                if not match:
                    continue
                try:
                    value = yaml.safe_load(match.group(1))
                except yaml.YAMLError:
                    continue
                if value == pattern:
                    matching_index = index
                    break

            if add and matching_index is None:
                inline_value = key_match.group(1)
                if inline_value:
                    if inline_value not in {"[]", "null", "~"}:
                        raise HTTPException(
                            status_code=500,
                            detail=(
                                f"Unsupported inline command_rules.{category} "
                                "value; use a YAML block list"
                            ),
                        )
                    lines[key_index] = f"  {category}:\n"
                insert_at = key_end
                while insert_at > key_index + 1:
                    previous = lines[insert_at - 1]
                    if not previous.strip() or previous.lstrip().startswith("#"):
                        insert_at -= 1
                        continue
                    break
                rendered_pattern = json.dumps(pattern, ensure_ascii=False)
                rendered_reason = json.dumps(reason, ensure_ascii=False)
                rule_action = {
                    "whitelist": "allow",
                    "blacklist": "deny",
                }[category]
                lines[insert_at:insert_at] = [
                    f"    - pattern: {rendered_pattern}\n",
                    f"      action: {rule_action}\n",
                    f"      reason: {rendered_reason}\n",
                    "\n",
                ]
            elif not add and matching_index is not None:
                remove_end = matching_index + 1
                while remove_end < key_end:
                    line = lines[remove_end]
                    if not line.strip():
                        break
                    indentation = len(line) - len(line.lstrip())
                    if (
                        indentation <= 2
                        or (indentation == 4 and line.lstrip().startswith("- "))
                    ):
                        break
                    remove_end += 1
                removed_count = remove_end - matching_index
                lines[matching_index:remove_end] = []
                key_end -= removed_count
                if not any(
                    re.match(
                        r"^\s{4}-\s+pattern:\s*(.*?)\s*$",
                        line,
                    )
                    for line in lines[key_index + 1:key_end]
                ):
                    lines[key_index] = f"  {category}: []\n"
            else:
                return False

            updated = "".join(lines)
            try:
                parsed = yaml.safe_load(updated)
                persisted_values = parsed["command_rules"][category]
                if not isinstance(persisted_values, list):
                    raise ValueError(
                        f"command_rules.{category} is not a list"
                    )
                if not all(
                    isinstance(item, Mapping)
                    and isinstance(item.get("pattern"), str)
                    for item in persisted_values
                ):
                    raise ValueError(
                        f"command_rules.{category} contains an invalid rule"
                    )
            except (KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Refusing to persist invalid rules YAML: {exc}",
                ) from exc

            mode = stat.S_IMODE(os.stat(path).st_mode)
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    newline="",
                    dir=os.path.dirname(path),
                    prefix=".rules.",
                    suffix=".tmp",
                    delete=False,
                ) as handle:
                    temp_path = handle.name
                    handle.write(updated)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_path, mode)
                os.replace(temp_path, path)
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unable to persist rules file: {exc}",
                ) from exc
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
            return True
    
    # Initialize components
    app.state.sanitizer = Sanitizer(
        patterns=rules_config.get("sanitizer_rules", {}).get("patterns"),
        skill_whitelist=rules_config.get("sanitizer_rules", {}).get("skill_whitelist", []),
    )
    app.state.rules = RuleEngine(rules_config)
    if app.state.rules.policy_overlaps:
        # An allow entry that overlaps a deny entry is dead policy: the deny
        # entry always wins, so the user's intent cannot take effect.
        print("⚠️  ClawGuard rules contain allow/deny overlaps (the deny entry always wins):")
        for overlap in app.state.rules.policy_overlaps:
            print(f"   - {overlap}")
        print("   Remove the overlap from one of the two lists in rules.yaml.")
    gateway_config = config.get("gateway", {}) if isinstance(config, dict) else {}
    gateway_config = gateway_config if isinstance(gateway_config, dict) else {}
    agent = agent_adapters.normalize_agent(
        getattr(settings, "agent", None)
        or os.environ.get("CLAWGUARD_AGENT")
        or gateway_config.get("agent")
        or "openclaw"
    )
    data_dir = os.path.expanduser(
        str(
            getattr(settings, "data_dir", None)
            or os.environ.get("CLAWGUARD_DATA_DIR")
            or gateway_config.get("data_dir")
            or gateway_config.get("dataDir")
            or os.path.join("~/.clawguard", "agents", agent)
        )
    )
    app.state.data_dir = data_dir
    audit_config = config.get("audit", {}) if isinstance(config, dict) else {}
    audit_config = audit_config if isinstance(audit_config, dict) else {}
    app.state.audit = AuditLogger(
        db_path=audit_config.get("db_path")
        or os.path.join(data_dir, "audit.db"),
    )
    approval_config = config.get("approval", {}) if isinstance(config, dict) else {}
    app.state.approval = ApprovalQueue(
        timeout_seconds=config.get("policy", {}).get("approval_timeout", 60),
        max_queue_size=approval_config.get("max_queue_size", 100),
        db_path=approval_config.get("db_path")
        or os.path.join(data_dir, "approval_history.db"),
    )
    app.state.timeout_action = config.get("policy", {}).get("timeout_action", "deny")
    app.state.panic = PanicManager()

    def task_scope_status() -> Dict[str, Any]:
        """Expose the latest active gateway session scope to the Dashboard."""
        locked = bool(getattr(app.state.rules, "task_scope_locked", False))
        gateway_scopes = getattr(app.state, "gateway_task_scopes", {})
        active_scopes = [
            state
            for state in gateway_scopes.values()
            if state.get("scope_ready") and isinstance(state.get("scope"), Mapping)
        ] if isinstance(gateway_scopes, Mapping) else []
        if active_scopes and not locked:
            latest = max(active_scopes, key=lambda state: state.get("updated_at", 0))
            return {
                "active": True,
                "locked": False,
                "rules": dict(latest["scope"]),
                "active_sessions": len(active_scopes),
            }
        return {
            "active": bool(app.state.rules.task_scope_active) and not locked,
            "locked": locked,
            "rules": app.state.rules.task_scope_rules,
            "active_sessions": 0,
        }

    async def clear_gateway_task_scopes(*, suppress_current_turn: bool) -> int:
        gateway_scopes = getattr(app.state, "gateway_task_scopes", {})
        session_locks = getattr(app.state, "gateway_session_locks", {})
        if not isinstance(gateway_scopes, dict):
            return 0
        cleared = 0

        def clear_state(state: Dict[str, Any]) -> None:
            state["scope"] = None
            state["scope_ready"] = False
            state["scope_registry_digest"] = None
            state["scope_suppressed_user_digest"] = (
                state.get("user_digest") if suppress_current_turn else None
            )

        for session_id in list(gateway_scopes):
            lock = session_locks.get(session_id) if isinstance(session_locks, dict) else None
            if lock is None:
                state = gateway_scopes.get(session_id)
                if isinstance(state, dict):
                    clear_state(state)
                    cleared += 1
                continue
            async with lock:
                state = gateway_scopes.get(session_id)
                if isinstance(state, dict):
                    clear_state(state)
                    cleared += 1
        return cleared
    
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
            return HTMLResponse(content=enhanced_path.read_text(encoding="utf-8"))
        
        # Fallback to original
        index_path = dashboard_dir / "index.html"
        if index_path.exists():
            return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
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
        gateway_settings = getattr(app.state, "gateway_settings", None)
        return {
            "agent": getattr(gateway_settings, "agent", agent),
            "upstream_format": getattr(
                gateway_settings,
                "upstream_format",
                "openai_chat_completion",
            ),
            "data_dir": app.state.data_dir,
            "panic": app.state.panic.get_status(),
            "approval": app.state.approval.get_stats(),
            "audit": app.state.audit.get_stats(hours=24),
            # The Dashboard consumes this scoped view so LLM transport and
            # approval bookkeeping do not appear as user-facing tool actions.
            "native_tool_audit": app.state.audit.get_stats(hours=24, native_only=True),
            "task_scope": task_scope_status(),
        }
    
    @app.get("/api/status")
    async def api_status():
        """Get API status for local administration clients."""
        stats = app.state.audit.get_stats(hours=24)
        gateway_settings = getattr(app.state, "gateway_settings", None)
        return {
            "version": "1.0.0",
            "mode": config.get("policy", {}).get("mode", "permissive"),
            "panic": app.state.panic.is_panicking,
            "pid": os.getpid(),
            "audit_total": stats.get("total_operations", 0),
            "audit_denied": stats.get("denied_count", 0),
            "responses_api": bool(
                getattr(gateway_settings, "enable_responses_api", False)
            ),
            "agent": getattr(gateway_settings, "agent", agent),
            "upstream_format": getattr(
                gateway_settings,
                "upstream_format",
                "openai_chat_completion",
            ),
            "data_dir": app.state.data_dir,
        }
    
    # ================================
    # Routes: Sanitizer
    # ================================
    
    @app.post("/api/tool/call")
    async def tool_call(request: ToolCallRequest):
        """Legacy local operation endpoint (not mounted by the LLM gateway)."""
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
                _log_path = os.path.join(
                    app.state.data_dir,
                    "read_debug.log",
                )
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
        
        result = app.state.rules.check_command(
            request.command,
            cwd=request.cwd or None,
        )
        
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
    async def get_approval_history(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        include_previous_runs: bool = Query(False),
    ):
        """Get current-process or persistent approval history."""
        if include_previous_runs:
            history = app.state.approval.get_persisted_history(
                limit=limit,
                offset=offset,
                include_previous_runs=True,
            )
            source = "persistent"
        else:
            history = [
                request.to_dict()
                for request in app.state.approval.get_history(limit)
            ]
            source = "current_process"
        return {
            "history": history,
            "source": source,
            "boot_id": app.state.approval.boot_id,
            "include_previous_runs": include_previous_runs,
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
    async def get_audit_stats(
        hours: int = Query(24, ge=1, le=168),
        native_only: bool = Query(False),
    ):
        """Get audit statistics"""
        return app.state.audit.get_stats(hours, native_only=native_only)
    
    @app.get("/audit/logs")
    async def get_audit_logs(
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        action: Optional[str] = None,
        result: Optional[str] = None,
        native_only: bool = Query(False),
    ):
        """Get audit logs.

        ``native_only`` is used by the Dashboard to show only native model-tool
        calls for the active Agent. Internal gateway events and plugin/MCP calls
        remain available to backend audit consumers when it is false.
        """
        logs = app.state.audit.query(
            action=action,
            result=result,
            limit=limit,
            offset=offset,
            native_only=native_only,
        )
        return {
            "count": len(logs),
            "native_only": native_only,
            "logs": [l.to_dict() for l in logs],
        }
    
    @app.get("/audit/download")
    async def download_audit_logs(
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        session_id: Optional[str] = None,
        native_only: bool = Query(False),
    ):
        """
        Download audit logs as JSON file
        
        Query Parameters:
        - start_time: Unix timestamp (optional, filter logs after this time)
        - end_time: Unix timestamp (optional, filter logs before this time)
        - action: Filter by action type (optional)
        - result: Filter by result (optional)
        - session_id: Filter by session ID (optional)
        - native_only: Export only native model-tool calls for the active Agent
          (optional)
        
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
            native_only=native_only,
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
                    "native_only": native_only,
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
            persist_rule_change(
                "network_rules",
                "allowed_domains",
                domain,
                add=True,
            )
            app.state.rules.network_rules["allowed_domains"].append(domain)
            return {"status": "added", "domain": domain, "persisted": True}
        return {"status": "already_exists", "domain": domain, "persisted": True}
    
    @app.post("/rules/network/deny")
    async def add_denied_domain(domain: str):
        """Add domain to network blacklist"""
        if domain not in app.state.rules.network_rules["denied_domains"]:
            persist_rule_change(
                "network_rules",
                "denied_domains",
                domain,
                add=True,
            )
            app.state.rules.network_rules["denied_domains"].append(domain)
            return {"status": "added", "domain": domain, "persisted": True}
        return {"status": "already_exists", "domain": domain, "persisted": True}
    
    @app.post("/rules/file/allow")
    async def add_allowed_path(path: str):
        """Add path to file whitelist"""
        expanded = os.path.expanduser(path)
        if expanded not in app.state.rules.file_rules["allowed_paths"]:
            persist_rule_change(
                "file_rules",
                "allowed_paths",
                expanded,
                add=True,
            )
            app.state.rules.file_rules["allowed_paths"].append(expanded)
            return {"status": "added", "path": expanded, "persisted": True}
        return {"status": "already_exists", "path": expanded, "persisted": True}
    
    @app.post("/rules/file/deny")
    async def add_denied_path(path: str):
        """Add path to file blacklist"""
        expanded = os.path.expanduser(path)
        if expanded not in app.state.rules.file_rules["denied_paths"]:
            persist_rule_change(
                "file_rules",
                "denied_paths",
                expanded,
                add=True,
            )
            app.state.rules.file_rules["denied_paths"].append(expanded)
            return {"status": "added", "path": expanded, "persisted": True}
        return {"status": "already_exists", "path": expanded, "persisted": True}
    
    @app.delete("/rules/network/allow/{domain}")
    async def remove_allowed_domain(domain: str):
        """Remove domain from network whitelist"""
        if domain in app.state.rules.network_rules["allowed_domains"]:
            persist_rule_change(
                "network_rules",
                "allowed_domains",
                domain,
                add=False,
            )
            app.state.rules.network_rules["allowed_domains"].remove(domain)
            return {"status": "removed", "domain": domain, "persisted": True}
        return {"status": "not_found", "domain": domain, "persisted": True}
    
    @app.delete("/rules/network/deny/{domain}")
    async def remove_denied_domain(domain: str):
        """Remove domain from network blacklist"""
        if domain in app.state.rules.network_rules["denied_domains"]:
            persist_rule_change(
                "network_rules",
                "denied_domains",
                domain,
                add=False,
            )
            app.state.rules.network_rules["denied_domains"].remove(domain)
            return {"status": "removed", "domain": domain, "persisted": True}
        return {"status": "not_found", "domain": domain, "persisted": True}
    
    @app.delete("/rules/file/allow")
    async def remove_allowed_path(path: str):
        """Remove path from file whitelist"""
        expanded = os.path.expanduser(path)
        if expanded in app.state.rules.file_rules["allowed_paths"]:
            persist_rule_change(
                "file_rules",
                "allowed_paths",
                expanded,
                add=False,
            )
            app.state.rules.file_rules["allowed_paths"].remove(expanded)
            return {"status": "removed", "path": expanded, "persisted": True}
        return {"status": "not_found", "path": expanded, "persisted": True}
    
    @app.delete("/rules/file/deny")
    async def remove_denied_path(path: str):
        """Remove path from file blacklist"""
        expanded = os.path.expanduser(path)
        if expanded in app.state.rules.file_rules["denied_paths"]:
            persist_rule_change(
                "file_rules",
                "denied_paths",
                expanded,
                add=False,
            )
            app.state.rules.file_rules["denied_paths"].remove(expanded)
            return {"status": "removed", "path": expanded, "persisted": True}
        return {"status": "not_found", "path": expanded, "persisted": True}
    
    @app.get("/rules/list")
    async def list_rules():
        """Get current runtime rules including task scope"""
        command_rule_groups = {
            "allowed": "whitelist",
            "denied": "blacklist",
        }
        return {
            "command": {
                public_name: [
                    {
                        "pattern": rule["raw_pattern"],
                        "reason": rule.get("reason", ""),
                    }
                    for rule in app.state.rules.command_rules[internal_name]
                ]
                for public_name, internal_name in command_rule_groups.items()
            },
            "network": {
                "allowed_domains": app.state.rules.network_rules["allowed_domains"],
                "denied_domains": app.state.rules.network_rules["denied_domains"],
            },
            "file": {
                "allowed_paths": app.state.rules.file_rules["allowed_paths"],
                "denied_paths": app.state.rules.file_rules["denied_paths"],
            },
            "task_scope": {
                **task_scope_status(),
            },
        }

    COMMAND_RULE_CATEGORIES = {
        "allow": "whitelist",
        "whitelist": "whitelist",
        "deny": "blacklist",
        "blacklist": "blacklist",
    }
    COMMAND_RULE_ACTIONS = {
        "whitelist": ActionType.ALLOW,
        "blacklist": ActionType.DENY,
    }
    COMMAND_RULE_REASONS = {
        "whitelist": "Command allowed from Dashboard",
        "blacklist": "Command blocked from Dashboard",
    }

    def resolve_command_category(category: str) -> str:
        resolved = COMMAND_RULE_CATEGORIES.get(category.strip().casefold())
        if resolved is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown command rule category: {category}",
            )
        return resolved

    @app.post("/rules/command/{category}")
    async def add_command_rule(
        category: str,
        pattern: str,
        reason: str = "",
    ):
        """Add one command regex to the selected command rule list."""
        canonical = resolve_command_category(category)
        pattern = pattern.strip()
        if not pattern:
            raise HTTPException(status_code=400, detail="Command pattern is required")
        if len(pattern) > 2048 or "\n" in pattern or "\r" in pattern:
            raise HTTPException(
                status_code=400,
                detail="Command pattern must be a single line up to 2048 characters",
            )
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid command regex: {exc}",
            ) from exc

        existing = app.state.rules.command_rules[canonical]
        if any(rule["raw_pattern"] == pattern for rule in existing):
            return {
                "status": "already_exists",
                "category": category,
                "pattern": pattern,
                "persisted": True,
            }

        reason = reason.strip()[:512] or COMMAND_RULE_REASONS[canonical]
        persist_command_rule_change(
            canonical,
            pattern,
            reason,
            add=True,
        )
        existing.append(
            {
                "pattern": compiled_pattern,
                "action": COMMAND_RULE_ACTIONS[canonical],
                "reason": reason,
                "raw_pattern": pattern,
            }
        )
        return {
            "status": "added",
            "category": category,
            "pattern": pattern,
            "persisted": True,
        }

    @app.delete("/rules/command/{category}")
    async def remove_command_rule(category: str, pattern: str):
        """Remove one exact command regex from the selected rule list."""
        canonical = resolve_command_category(category)
        existing = app.state.rules.command_rules[canonical]
        matching = next(
            (
                rule
                for rule in existing
                if rule["raw_pattern"] == pattern
            ),
            None,
        )
        if matching is None:
            return {
                "status": "not_found",
                "category": category,
                "pattern": pattern,
                "persisted": True,
            }

        persist_command_rule_change(
            canonical,
            pattern,
            matching.get("reason", ""),
            add=False,
        )
        existing.remove(matching)
        return {
            "status": "removed",
            "category": category,
            "pattern": pattern,
            "persisted": True,
        }

    @app.post("/task-scope/lock")
    async def lock_task_scope():
        # Locking only changes which policy view is active.  Keep per-session
        # scopes dormant so unlocking can resume the same turn without another
        # task-scope planner request.
        return app.state.rules.lock_task_scope()
    
    @app.post("/task-scope/unlock")
    async def unlock_task_scope():
        return app.state.rules.unlock_task_scope()
    
    @app.post("/task-scope/clear")
    async def clear_task_scope_route():
        result = app.state.rules.clear_task_scope()
        result["gateway_sessions_cleared"] = await clear_gateway_task_scopes(
            suppress_current_turn=True
        )
        return result

    return app


# Default application
app = create_app(
    config_path=os.path.expanduser("~/.clawguard/config.yaml"),
    rules_path=os.path.expanduser("~/.clawguard/rules.yaml"),
)
