"""
Emergency Panic Module (Panic Module)
One-click block all Agent operations, supports multiple trigger methods
"""

import asyncio
import time
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class PanicState(Enum):
    """Panic Status"""
    NORMAL = "normal"
    PANIC = "panic"


class PanicTrigger(Enum):
    """Panic Trigger Source"""
    CLI = "cli"
    DASHBOARD = "dashboard"
    CLOUD = "cloud"
    API = "api"
    AUTO = "auto"


@dataclass
class PanicRecord:
    """Panic Record"""
    timestamp: float = field(default_factory=time.time)
    state: str = PanicState.NORMAL.value
    trigger: str = ""
    reason: str = ""
    triggered_by: str = ""
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None


class PanicManager:
    """
    Panic Manager
    
    Features:
    - One-click Panic: immediately block all Agent operations
    - Resume: restore after confirming safety
    - Support three trigger methods: local CLI, Dashboard, remote cloud
    - Record Panic history
    """
    
    def __init__(self):
        """Initialize Panic """
        self._state = PanicState.NORMAL
        self._current_panic: Optional[PanicRecord] = None
        self._history: list[PanicRecord] = []
        self._on_panic_callbacks: list[Callable] = []
        self._on_resume_callbacks: list[Callable] = []
        self._subscribers: list[asyncio.Queue] = []
    
    @property
    def is_panicking(self) -> bool:
        """ Panic Status"""
        return self._state == PanicState.PANIC
    
    @property
    def state(self) -> PanicState:
        """"""
        return self._state
    
    def get_status(self) -> Dict[str, Any]:
        """ Panic StatusInformation"""
        return {
            "state": self._state.value,
            "is_panicking": self.is_panicking,
            "current_panic": self._current_panic.__dict__ if self._current_panic else None,
            "panic_count": len([r for r in self._history if r.state == PanicState.PANIC.value]),
            "last_update": datetime.now().isoformat(),
        }
    
    async def panic(
        self,
        trigger: PanicTrigger = PanicTrigger.API,
        reason: str = "",
        triggered_by: str = "system",
    ) -> PanicRecord:
        """
         Panic - Operation
        
        Args:
            trigger: Trigger source
            reason: Trigger reason
            triggered_by: Triggered by
            
        Returns:
            Panic Record
        """
        if self.is_panicking:
            return self._current_panic
        
        self._state = PanicState.PANIC
        
        record = PanicRecord(
            state=PanicState.PANIC.value,
            trigger=trigger.value,
            reason=reason,
            triggered_by=triggered_by,
        )
        
        self._current_panic = record
        self._history.append(record)
        
        # 
        for callback in self._on_panic_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(record)
                else:
                    callback(record)
            except Exception as e:
                print(f"Panic callback error: {e}")
        
        # Subscribers
        await self._broadcast({
            "event": "panic",
            "data": record.__dict__
        })
        
        return record
    
    async def resume(
        self,
        resolved_by: str = "system",
        reason: str = "",
    ) -> Optional[PanicRecord]:
        """
         -  Panic Status
        
        Args:
            resolved_by: 
            reason: Reason
            
        Returns:
             Panic Record
        """
        if not self.is_panicking:
            return None
        
        self._state = PanicState.NORMAL
        
        if self._current_panic:
            self._current_panic.resolved_at = time.time()
            self._current_panic.resolved_by = resolved_by
            # History records
            for record in self._history:
                if record.timestamp == self._current_panic.timestamp:
                    record.resolved_at = self._current_panic.resolved_at
                    record.resolved_by = resolved_by
                    break
        
        record = self._current_panic
        self._current_panic = None
        
        # 
        for callback in self._on_resume_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(record)
                else:
                    callback(record)
            except Exception as e:
                print(f"Resume callback error: {e}")
        
        # Subscribers
        await self._broadcast({
            "event": "resume",
            "data": {
                "resolved_by": resolved_by,
                "reason": reason,
                "resolved_at": time.time(),
            }
        })
        
        return record
    
    def check(self) -> bool:
        """
        AllowOperation
        
        Returns:
            True AllowOperation，False 
        """
        return not self.is_panicking
    
    def block_if_panicking(self) -> None:
        """
         Panic Status，
        
        Raises:
            RuntimeError:  Panic Status
        """
        if self.is_panicking:
            raise RuntimeError(
                f"🚨 ClawGuard  Panic Status，Operation。\n"
                f"Reason: {self._current_panic.reason if self._current_panic else ''}\n"
                f" resume() Operation。"
            )
    
    # ================================
    # 
    # ================================
    
    def on_panic(self, callback: Callable):
        """ Panic """
        self._on_panic_callbacks.append(callback)
    
    def on_resume(self, callback: Callable):
        """ Resume """
        self._on_resume_callbacks.append(callback)
    
    # ================================
    # SSE 
    # ================================
    
    async def subscribe(self) -> asyncio.Queue:
        """ Panic Event"""
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
            # First send current state
            yield {
                "event": "status",
                "data": json.dumps(self.get_status())
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
                        "data": json.dumps(self.get_status())
                    }
        finally:
            await self.unsubscribe(queue)
    
    # ================================
    # History records
    # ================================
    
    def get_history(self, limit: int = 50) -> list[PanicRecord]:
        """ Panic History"""
        return self._history[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Information"""
        panic_count = len([r for r in self._history if r.state == PanicState.PANIC.value])
        
        total_duration = 0.0
        for record in self._history:
            if record.resolved_at and record.state == PanicState.PANIC.value:
                total_duration += record.resolved_at - record.timestamp
        
        return {
            "total_panics": panic_count,
            "total_duration_seconds": total_duration,
            "current_state": self._state.value,
            "history_count": len(self._history),
        }