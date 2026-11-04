"""
Approval Queue Module (Approval Queue Module)
Handles operations requiring approval, supports REST API and SSE real-time push
"""

import asyncio
import os
import time
import uuid
import sqlite3
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
from collections import OrderedDict
from contextlib import closing
from sse_starlette.sse import EventSourceResponse


class ApprovalStatus(Enum):
    """Approval Status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"


class ApprovalType(Enum):
    """Approval Type"""
    COMMAND = "command"
    FILE_WRITE = "file_write"
    FILE_READ_SENSITIVE = "file_read_sensitive"
    NETWORK = "network"
    SKILL = "skill"
    TOOL_CALL = "tool_call"


@dataclass
class ApprovalRequest:
    """Approval Request"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: float = field(default_factory=time.time)
    approval_type: str = ""
    operation: str = ""
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = ApprovalStatus.PENDING.value
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None
    resolution_reason: Optional[str] = None
    # Event used for blocking wait — set when approve() or deny() is called
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False, compare=False)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "created_at_human": datetime.fromtimestamp(self.created_at).isoformat(),
            "approval_type": self.approval_type,
            "operation": self.operation,
            "reason": self.reason,
            "details": self.details,
            "status": self.status,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolution_reason": self.resolution_reason,
        }


class ApprovalQueue:
    """
    Approval Queue
    
    Features:
    - Manage pending approval operations
    - Support approve/deny operations
    - SSE real-time push approval events
    - Auto-handle timeout
    """
    
    def __init__(
        self,
        timeout_seconds: int = 60,
        max_queue_size: int = 100,
        db_path: Optional[str] = None,
    ):
        """
        InitializeApproval Queue
        
        Args:
            timeout_seconds: Approval timeout duration（seconds）
            max_queue_size: Maximum queue size
        """
        self.timeout_seconds = timeout_seconds
        self.max_queue_size = max_queue_size
        self.boot_id = uuid.uuid4().hex
        self.db_path = (
            os.path.expanduser(db_path)
            if db_path
            else os.path.expanduser("~/.clawguard/approval_history.db")
        )
        
        # PendingApproval Queue（Ordered dict, sorted by time）
        self._pending: OrderedDict[str, ApprovalRequest] = OrderedDict()
        
        # ProcessedHistory records
        self._history: List[ApprovalRequest] = []
        
        # SSE Subscribers
        self._subscribers: List[asyncio.Queue] = []
        
        # Callback function
        self._on_resolution: Optional[Callable] = None
        self._init_history_db()

    def _history_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_history_db(self) -> None:
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        with closing(self._history_connection()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_history (
                    id TEXT PRIMARY KEY,
                    boot_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    approval_type TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    reason TEXT,
                    details TEXT,
                    status TEXT NOT NULL,
                    resolved_at REAL,
                    resolved_by TEXT,
                    resolution_reason TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_created "
                "ON approval_history(created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_boot "
                "ON approval_history(boot_id)"
            )
            conn.execute(
                """
                UPDATE approval_history
                SET status = ?,
                    resolved_at = ?,
                    resolution_reason = ?
                WHERE status = ? AND boot_id <> ?
                """,
                (
                    ApprovalStatus.INTERRUPTED.value,
                    time.time(),
                    "ClawGuard restarted before approval resolution",
                    ApprovalStatus.PENDING.value,
                    self.boot_id,
                ),
            )
            conn.commit()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _persist_request(self, request: ApprovalRequest) -> None:
        with closing(self._history_connection()) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO approval_history
                (id, boot_id, created_at, approval_type, operation, reason,
                 details, status, resolved_at, resolved_by, resolution_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    self.boot_id,
                    request.created_at,
                    request.approval_type,
                    request.operation,
                    request.reason,
                    json.dumps(request.details, ensure_ascii=False),
                    request.status,
                    request.resolved_at,
                    request.resolved_by,
                    request.resolution_reason,
                ),
            )
            conn.commit()
    
    def set_on_resolution(self, callback: Callable):
        """Result"""
        self._on_resolution = callback
    
    async def add_request(
        self,
        approval_type: ApprovalType,
        operation: str,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Approval Request
        
        Args:
            approval_type: Approval Type
            operation: Operation
            reason: Approval reason
            details: 
            
        Returns:
            createdApproval Request
        """
        request = ApprovalRequest(
            approval_type=approval_type.value,
            operation=operation,
            reason=reason,
            details=details or {},
        )

        self._persist_request(request)
        self._pending[request.id] = request
        
        # Subscribers
        await self._broadcast({
            "event": "new_request",
            "data": request.to_dict()
        })
        
        return request
    
    def get_pending(self) -> List[ApprovalRequest]:
        """PendingApproval Request"""
        return list(self._pending.values())
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Approval Request"""
        return self._pending.get(request_id)
    
    async def approve(
        self,
        request_id: str,
        resolved_by: str = "system",
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """
        Approval Request
        
        Args:
            request_id:  ID
            resolved_by: 
            reason: Reason
            
        Returns:
            Approval Request
        """
        request = self._pending.get(request_id)
        if not request:
            return None
        
        request.status = ApprovalStatus.APPROVED.value
        request.resolved_at = time.time()
        request.resolved_by = resolved_by
        request.resolution_reason = reason
        self._persist_request(request)
        self._pending.pop(request_id, None)
        
        # History
        self._history.append(request)
        
        # Unblock any wait_for_decision() waiter
        request._event.set()
        
        # Subscribers
        await self._broadcast({
            "event": "approved",
            "data": request.to_dict()
        })
        
        # 
        if self._on_resolution:
            await self._on_resolution(request)
        
        return request
    
    async def deny(
        self,
        request_id: str,
        resolved_by: str = "system",
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """
        DenyApproval Request
        
        Args:
            request_id:  ID
            resolved_by: Deny
            reason: DenyReason
            
        Returns:
            Approval Request
        """
        request = self._pending.get(request_id)
        if not request:
            return None
        
        request.status = ApprovalStatus.DENIED.value
        request.resolved_at = time.time()
        request.resolved_by = resolved_by
        request.resolution_reason = reason
        self._persist_request(request)
        self._pending.pop(request_id, None)
        
        # History
        self._history.append(request)
        
        # Unblock any wait_for_decision() waiter
        request._event.set()
        
        # Subscribers
        await self._broadcast({
            "event": "denied",
            "data": request.to_dict()
        })
        
        # 
        if self._on_resolution:
            await self._on_resolution(request)
        
        return request
    
    async def wait_for_decision(
        self,
        request_id: str,
        timeout: Optional[int] = None,
    ) -> ApprovalRequest:
        """
        Block until the request is approved, denied, or times out.
        Uses asyncio.Event for instant unblocking — no polling.

        Args:
            request_id: Approval request ID
            timeout: Max seconds to wait (defaults to self.timeout_seconds)

        Returns:
            ApprovalRequest with final status (APPROVED / DENIED / TIMEOUT)
        """
        timeout = timeout or self.timeout_seconds

        request = self._pending.get(request_id)
        if request is None:
            raise RuntimeError(f"Request {request_id} not found")

        try:
            # Block here until approve() or deny() fires _event.set()
            await asyncio.wait_for(request._event.wait(), timeout=float(timeout))
        except asyncio.TimeoutError:
            # Timeout — move to history as TIMEOUT
            self._pending.pop(request_id, None)
            request.status = ApprovalStatus.TIMEOUT.value
            request.resolved_at = time.time()
            request.resolution_reason = f"Approval timed out after {timeout}s"
            self._persist_request(request)
            self._history.append(request)
            await self._broadcast({"event": "timeout", "data": request.to_dict()})

        return request

    # Keep wait_for_resolution as an alias for backward compatibility
    async def wait_for_resolution(
        self,
        request_id: str,
        timeout: Optional[int] = None,
    ) -> ApprovalRequest:
        return await self.wait_for_decision(request_id, timeout)
    
    def get_history(self, limit: int = 50) -> List[ApprovalRequest]:
        """History"""
        return self._history[-limit:]

    def get_persisted_history(
        self,
        limit: int = 100,
        offset: int = 0,
        include_previous_runs: bool = False,
    ) -> List[Dict[str, Any]]:
        """Read approval records from persistent storage."""
        where = "" if include_previous_runs else "WHERE boot_id = ?"
        params: List[Any] = [] if include_previous_runs else [self.boot_id]
        params.extend([limit, offset])
        with closing(self._history_connection()) as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM approval_history
                {where}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params,
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.get("details") or "{}")
            except (TypeError, ValueError):
                item["details"] = {}
            item["created_at_human"] = datetime.fromtimestamp(
                item["created_at"]
            ).isoformat()
            if item.get("resolved_at"):
                item["resolved_at_human"] = datetime.fromtimestamp(
                    item["resolved_at"]
                ).isoformat()
            result.append(item)
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Information"""
        pending_count = len(self._pending)
        
        approved_count = sum(
            1 for r in self._history if r.status == ApprovalStatus.APPROVED.value
        )
        denied_count = sum(
            1 for r in self._history if r.status == ApprovalStatus.DENIED.value
        )
        timeout_count = sum(
            1 for r in self._history if r.status == ApprovalStatus.TIMEOUT.value
        )
        
        return {
            "pending": pending_count,
            "approved": approved_count,
            "denied": denied_count,
            "timeout": timeout_count,
            "total_processed": len(self._history),
        }
    
    async def cleanup_expired(self) -> int:
        """Approval Request"""
        now = time.time()
        expired = []
        
        for request_id, request in self._pending.items():
            if now - request.created_at > self.timeout_seconds:
                expired.append(request_id)
        
        for request_id in expired:
            request = self._pending.pop(request_id)
            request.status = ApprovalStatus.TIMEOUT.value
            request.resolved_at = now
            request.resolution_reason = "Approval timeout"
            self._persist_request(request)
            self._history.append(request)
            
            await self._broadcast({
                "event": "timeout",
                "data": request.to_dict()
            })
        
        return len(expired)
    
    # ================================
    # SSE 
    # ================================
    
    async def subscribe(self) -> asyncio.Queue:
        """Event"""
        queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue
    
    async def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe"""
        if queue in self._subscribers:
            self._subscribers.remove(queue)
    
    async def _broadcast(self, message: Dict[str, Any]):
        """Subscribers"""
        for queue in self._subscribers:
            try:
                await queue.put(message)
            except Exception:
                pass
    
    async def sse_stream(self):
        """ SSE Event stream"""
        queue = await self.subscribe()
        
        try:
            # First send current pending approval list
            yield {
                "event": "initial",
                "data": json.dumps([r.to_dict() for r in self.get_pending()])
            }
            
            # Event
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {
                        "event": message.get("event", "update"),
                        "data": json.dumps(message.get("data", {}))
                    }
                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield {
                        "event": "heartbeat",
                        "data": json.dumps({"timestamp": time.time()})
                    }
        finally:
            await self.unsubscribe(queue)
