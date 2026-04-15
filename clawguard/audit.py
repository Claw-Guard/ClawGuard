"""
Audit Log Module (Audit Logger Module)
Uses SQLite to record all operations, supports query and statistics
"""

import os
import json
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from contextlib import contextmanager


class AuditAction(Enum):
    """Audit Operation Type"""
    COMMAND_EXEC = "command_exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_REQUEST = "network_request"
    SKILL_CHECK = "skill_check"
    PANIC_TRIGGER = "panic_trigger"
    APPROVAL_APPROVE = "approval_approve"
    APPROVAL_DENY = "approval_deny"
    RULE_DENY = "rule_deny"


class AuditResult(Enum):
    """Audit Result"""
    ALLOWED = "allowed"
    DENIED = "denied"
    APPROVED = "approved"
    PENDING = "pending"
    ERROR = "error"


@dataclass
class AuditEntry:
    """Audit Log Entry"""
    id: Optional[int] = None
    timestamp: float = 0.0
    action: str = ""
    result: str = ""
    operation: str = ""
    reason: str = ""
    details: str = "{}"  # Additional details in JSON format
    session_id: str = ""
    agent_id: str = ""
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """
    Audit Logger
    
    Features:
    - Record all AI Agent operations
    - Support query and statistics
    - Auto-clean expired logs
    """
    
    # Create table SQL
    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        action TEXT NOT NULL,
        result TEXT NOT NULL,
        operation TEXT NOT NULL,
        reason TEXT,
        details TEXT,
        session_id TEXT,
        agent_id TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_result ON audit_log(result);
    """
    
    def __init__(
        self,
        db_path: str = "~/.clawguard/audit.db",
        max_size_mb: int = 500,
        retention_days: int = 90,
    ):
        """
        Initialize audit log
        
        Args:
            db_path: Database path
            max_size_mb: Max database size (MB)
            retention_days: Log retention days
            retention_days: Retention days
        """
        self.db_path = os.path.expanduser(db_path)
        self.max_size_mb = max_size_mb
        self.retention_days = retention_days
        
        # Create directory if needed
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database tables"""
        with self._get_connection() as conn:
            conn.executescript(self.CREATE_TABLE_SQL)
            conn.commit()
    
    def log(
        self,
        action: AuditAction,
        result: AuditResult,
        operation: str,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
        session_id: str = "",
        agent_id: str = "",
    ) -> int:
        """
        Record audit log
        
        Args:
            action: Operation type
            result: Operation result
            operation: Operation content
            reason: Reason description
            details: Additional details
            session_id: Session ID
            agent_id: Agent ID
            
        Returns:
            Log entry ID
        """
        entry = AuditEntry(
            timestamp=time.time(),
            action=action.value,
            result=result.value,
            operation=operation,
            reason=reason,
            details=json.dumps(details or {}, ensure_ascii=False),
            session_id=session_id,
            agent_id=agent_id,
        )
        
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log 
                (timestamp, action, result, operation, reason, details, session_id, agent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp,
                    entry.action,
                    entry.result,
                    entry.operation,
                    entry.reason,
                    entry.details,
                    entry.session_id,
                    entry.agent_id,
                )
            )
            conn.commit()
            return cursor.lastrowid
    
    def log_command(
        self,
        command: str,
        result: AuditResult,
        reason: str = "",
        session_id: str = "",
        agent_id: str = "",
    ) -> int:
        """Log command execution"""
        return self.log(
            action=AuditAction.COMMAND_EXEC,
            result=result,
            operation=command,
            reason=reason,
            session_id=session_id,
            agent_id=agent_id,
        )
    
    def log_file_access(
        self,
        path: str,
        operation: str,  # "read" or "write"
        result: AuditResult,
        reason: str = "",
        session_id: str = "",
        agent_id: str = "",
    ) -> int:
        """Log file access"""
        action = AuditAction.FILE_READ if operation == "read" else AuditAction.FILE_WRITE
        return self.log(
            action=action,
            result=result,
            operation=path,
            reason=reason,
            session_id=session_id,
            agent_id=agent_id,
        )
    
    def log_network(
        self,
        url: str,
        result: AuditResult,
        reason: str = "",
        session_id: str = "",
        agent_id: str = "",
    ) -> int:
        """Log network request"""
        return self.log(
            action=AuditAction.NETWORK_REQUEST,
            result=result,
            operation=url,
            reason=reason,
            session_id=session_id,
            agent_id=agent_id,
        )
    
    def query(
        self,
        action: Optional[str] = None,
        result: Optional[str] = None,
        session_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """
        Query audit logs
        
        Args:
            action: Operation type
            result: Result
            session_id: Session ID
            start_time: Start timestamp
            end_time: End timestamp
            limit: Max results
            offset: Offset
            
        Returns:
            List of matched log entries
        """
        conditions = []
        params = []
        
        if action:
            conditions.append("action = ?")
            params.append(action)
        if result:
            conditions.append("result = ?")
            params.append(result)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        sql = f"""
            SELECT * FROM audit_log 
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        
        with self._get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_entry(row) for row in rows]
    
    def _row_to_entry(self, row: sqlite3.Row) -> AuditEntry:
        """Convert database row to AuditEntry"""
        return AuditEntry(
            id=row["id"],
            timestamp=row["timestamp"],
            action=row["action"],
            result=row["result"],
            operation=row["operation"],
            reason=row["reason"],
            details=row["details"],
            session_id=row["session_id"],
            agent_id=row["agent_id"],
        )
    
    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get statistics
        
        Args:
            hours: Time range in hours
            
        Returns:
            Statistics information
        """
        start_time = time.time() - (hours * 3600)
        
        with self._get_connection() as conn:
            # Total operations
            total = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?",
                (start_time,)
            ).fetchone()[0]
            
            # By result
            by_result = conn.execute(
                """
                SELECT result, COUNT(*) as count 
                FROM audit_log 
                WHERE timestamp >= ?
                GROUP BY result
                """,
                (start_time,)
            ).fetchall()
            
            # By operation type
            by_action = conn.execute(
                """
                SELECT action, COUNT(*) as count 
                FROM audit_log 
                WHERE timestamp >= ?
                GROUP BY action
                """,
                (start_time,)
            ).fetchall()
            
            # Denied count
            denied = conn.execute(
                """
                SELECT COUNT(*) FROM audit_log 
                WHERE timestamp >= ? AND result = 'denied'
                """,
                (start_time,)
            ).fetchone()[0]
            
            return {
                "total_operations": total,
                "denied_count": denied,
                "by_result": {row["result"]: row["count"] for row in by_result},
                "by_action": {row["action"]: row["count"] for row in by_action},
                "hours": hours,
            }
    
    def cleanup(self):
        """Clean up old logs"""
        cutoff_time = time.time() - (self.retention_days * 86400)
        
        with self._get_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                (cutoff_time,)
            ).rowcount
            conn.commit()
        
        return deleted
    
    def get_size_mb(self) -> float:
        """Get database size in MB"""
        if os.path.exists(self.db_path):
            return os.path.getsize(self.db_path) / (1024 * 1024)
        return 0.0