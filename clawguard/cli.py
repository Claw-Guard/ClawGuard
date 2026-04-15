#!/usr/bin/env python3
"""
ClawGuard CLI - Command Line Interface
Manage ClawGuard daemon and security operations
"""

import os
import sys
import json
import time
import signal
import subprocess
import argparse
from pathlib import Path
from typing import Optional

import yaml
import httpx


# Approval queueDefault configuration
DEFAULT_CONFIG_DIR = Path.home() / ".clawguard"
DEFAULT_API_PORT = 19821
DEFAULT_WEB_PORT = 19821


class ClawGuardCLI:
    """ClawGuard CLI Tool"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_file = self.config_dir / "config.yaml"
        self.pid_file = self.config_dir / "daemon.pid"
        self.api_url = f"http://127.0.0.1:{DEFAULT_API_PORT}"
    
    def _get_pid(self) -> Optional[int]:
        """Get daemon PID"""
        if self.pid_file.exists():
            try:
                return int(self.pid_file.read_text().strip())
            except ValueError:
                return None
        return None
    
    def _is_running(self) -> bool:
        """Check if daemon is running"""
        pid = self._get_pid()
        if pid:
            try:
                os.kill(pid, 0)  # Check if process exists
                return True
            except OSError:
                return False
        return False
    
    def _check_api(self) -> bool:
        """Check if API responds"""
        try:
            resp = httpx.get(f"{self.api_url}/", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            return False
    
    def start(self):
        """Start daemon"""
        if self._check_api():
            print("✅ ClawGuard daemon is already running")
            return
        
        print("🚀 Starting ClawGuard daemon...")
        
        # 
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Start uvicorn
        import uvicorn
        from clawguard.api import create_app
        
        # Write PID
        pid = os.getpid()
        self.pid_file.write_text(str(pid))
        
        # Start service
        config_path = self.config_dir / "config.yaml"
        rules_path = self.config_dir / "rules.yaml"
        
        app = create_app(
            config_path=str(config_path) if config_path.exists() else None,
            rules_path=str(rules_path) if rules_path.exists() else None,
        )
        
        print(f"📡 API Server: http://127.0.0.1:{DEFAULT_API_PORT}")
        print(f"🌐 Dashboard: http://127.0.0.1:{DEFAULT_API_PORT}/")
        print("Press Ctrl+C to stop")
        
        try:
            uvicorn.run(
                app,
                host="127.0.0.1",
                port=DEFAULT_API_PORT,
                log_level="info",
            )
        finally:
            if self.pid_file.exists():
                self.pid_file.unlink()
    
    def stop(self):
        """Stop daemon"""
        pid = self._get_pid()
        if not pid:
            print("⚠️  ClawGuard daemon is not running")
            return
        
        try:
            os.kill(pid, signal.SIGTERM)
            print("🛑 ClawGuard daemon stopped")
        except OSError:
            print("⚠️  Failed to stop daemon")
        
        if self.pid_file.exists():
            self.pid_file.unlink()
    
    def status(self):
        "Show status"
        print("🛡️  ClawGuard Status\n")
        
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            print(f"\n  Start with: clawguard daemon start")
            return
        
        try:
            resp = httpx.get(f"{self.api_url}/status", timeout=5.0)
            data = resp.json()
            
            # Panic status
            panic = data.get("panic", {})
            state = panic.get("state", "unknown")
            state_emoji = "🔴" if state == "panic" else "🟢"
            print(f"  Status:   {state_emoji} {state}")
            
            # 
            approval = data.get("approval", {})
            print(f"  Pending: {approval.get('pending', 0)}")
            print(f"  : {approval.get('approved', 0)}")
            print(f"  Denied: {approval.get('denied', 0)}")
            
            # 
            audit = data.get("audit", {})
            print(f"\n  📊  Audit Stats (last {audit.get('hours', 24)} hours)")
            print(f"  Total Operations: {audit.get('total_operations', 0)}")
            print(f"  Denied: {audit.get('denied_count', 0)}")
            
        except Exception as e:
            print(f"❌ Failed to resume: {e}")
    
    def panic(self, reason: str = ""):
        """Trigger emergency panic"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/panic",
                json={"reason": reason or "CLI triggered panic", "trigger": "cli"},
                timeout=5.0,
            )
            data = resp.json()
            print(f"🚨 PANIC MODE ACTIVATED! All agent operations blocked.")
            print(f"   Reason: {data.get('record', {}).get('reason', '')}")
        except Exception as e:
            print(f"❌ Failed to trigger panic: {e}")
    
    def resume(self, reason: str = ""):
        """Resume normal operations"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/resume",
                json={"resolved_by": "cli", "reason": reason},
                timeout=5.0,
            )
            data = resp.json()
            print(f"✅ ClawGuard resumed normal operations")
        except Exception as e:
            print(f"❌ : {e}")
    
    def check_command(self, command: str):
        """Check command"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/check/command",
                json={"command": command},
                timeout=5.0,
            )
            data = resp.json()
            
            if data.get("allowed"):
                print(f"✅ Allow: {data.get('reason', '')}")
            else:
                print(f"🚫 Deny: {data.get('reason', '')}")
                if data.get("pattern"):
                    print(f"   Match rule: {data.get('pattern')}")
        except Exception as e:
            print(f"❌ : {e}")
    
    def check_file(self, path: str, operation: str = "read"):
        """FilePath"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/check/file",
                json={"path": path, "operation": operation},
                timeout=5.0,
            )
            data = resp.json()
            
            if data.get("allowed"):
                print(f"✅ Allow: {data.get('reason', '')}")
            else:
                print(f"🚫 Deny: {data.get('reason', '')}")
        except Exception as e:
            print(f"❌ : {e}")
    
    def sanitize(self, text: str):
        """Sanitize text"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/sanitize",
                json={"text": text},
                timeout=5.0,
            )
            data = resp.json()
            print(f"📝 Result:\n{data.get('sanitized', '')}")
        except Exception as e:
            print(f"❌ : {e}")
    
    def show_approvals(self):
        """PendingList"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.get(f"{self.api_url}/approval/pending", timeout=5.0)
            data = resp.json()
            
            requests = data.get("requests", [])
            if not requests:
                print("✅ PendingOperation")
                return
            
            print(f"📋 PendingList ({len(requests)} ):\n")
            for req in requests:
                print(f"  [{req['id']}] {req['approval_type']}: {req['operation']}")
                print(f"      Reason: {req['reason']}")
                print()
        except Exception as e:
            print(f"❌ : {e}")
    
    def approve(self, request_id: str, reason: str = ""):
        """Approve request"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/approval/approve",
                json={"request_id": request_id, "resolved_by": "cli", "reason": reason},
                timeout=5.0,
            )
            data = resp.json()
            print(f"✅ : {request_id}")
        except Exception as e:
            print(f"❌ : {e}")
    
    def deny(self, request_id: str, reason: str = ""):
        """Deny request"""
        if not self._check_api():
            print("⚠️  ClawGuard daemon ")
            return
        
        try:
            resp = httpx.post(
                f"{self.api_url}/approval/deny",
                json={"request_id": request_id, "resolved_by": "cli", "reason": reason},
                timeout=5.0,
            )
            data = resp.json()
            print(f"🚫 Deny: {request_id}")
        except Exception as e:
            print(f"❌ Deny: {e}")
    
    def init(self):
        """Initialize config directory，Default configurationFile"""
        import shutil
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Find project config directory
        project_root = Path(__file__).parent.parent
        src_config = project_root / "config" / "config.yaml"
        src_rules = project_root / "config" / "rules.yaml"
        
        dst_config = self.config_dir / "config.yaml"
        dst_rules = self.config_dir / "rules.yaml"
        
        copied = []
        skipped = []
        
        for src, dst in [(src_config, dst_config), (src_rules, dst_rules)]:
            if dst.exists():
                skipped.append(dst.name)
            elif src.exists():
                shutil.copy2(src, dst)
                copied.append(dst.name)
            else:
                print(f"⚠️  Source not found: {src}")
        
        if copied:
            print(f"✅ Initialized: {', '.join(copied)} → {self.config_dir}")
        if skipped:
            print(f"ℹ️  Already exists (skipped): {', '.join(skipped)}")
        
        print(f"\n📂 Config dir: {self.config_dir}")
        print(f"   Edit {self.config_dir}/rules.yaml to customize security rules.")


def main():
    """CLI Entry point"""
    parser = argparse.ArgumentParser(
        description="🛡️ ClawGuard - AI Agent Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # daemon Command
    daemon_parser = subparsers.add_parser("daemon", help=" Daemon ")
    daemon_parser.add_argument("action", choices=["start", "stop", "status"], help="Operation")
    
    # panic Command
    panic_parser = subparsers.add_parser("panic", help="🚨 ")
    panic_parser.add_argument("--reason", "-r", default="", help="Reason")
    
    # resume Command
    resume_parser = subparsers.add_parser("resume", help="Resume normal operations")
    resume_parser.add_argument("--reason", "-r", default="", help="Reason")
    
    # status Command
    subparsers.add_parser("status", help="Check status")
    
    # check Command
    check_parser = subparsers.add_parser("check", help="")
    check_parser.add_argument("type", choices=["command", "file", "network"], help="Type")
    check_parser.add_argument("target", help="")
    check_parser.add_argument("--operation", "-o", default="read", help="FileOperationType")
    
    # sanitize Command
    sanitize_parser = subparsers.add_parser("sanitize", help="Information")
    sanitize_parser.add_argument("text", help="")
    
    # approval Command
    approval_parser = subparsers.add_parser("approval", help="")
    approval_parser.add_argument("action", choices=["list", "approve", "deny"], help="Operation")
    approval_parser.add_argument("--id", "-i", help=" ID")
    approval_parser.add_argument("--reason", "-r", default="", help="Reason")
    
    # init
    subparsers.add_parser("init", help="Initialize config directory（Default configuration）")
    
    # version
    subparsers.add_parser("version", help="Information")
    
    args = parser.parse_args()
    
    cli = ClawGuardCLI()
    
    if args.command == "daemon":
        if args.action == "start":
            cli.start()
        elif args.action == "stop":
            cli.stop()
        elif args.action == "status":
            cli.status()
    
    elif args.command == "panic":
        cli.panic(args.reason)
    
    elif args.command == "resume":
        cli.resume(args.reason)
    
    elif args.command == "status":
        cli.status()
    
    elif args.command == "check":
        if args.type == "command":
            cli.check_command(args.target)
        elif args.type == "file":
            cli.check_file(args.target, args.operation)
        elif args.type == "network":
            print("Network")
    
    elif args.command == "sanitize":
        cli.sanitize(args.text)
    
    elif args.command == "approval":
        if args.action == "list":
            cli.show_approvals()
        elif args.action == "approve":
            if not args.id:
                print("❌  ID: --id <id>")
                sys.exit(1)
            cli.approve(args.id, args.reason)
        elif args.action == "deny":
            if not args.id:
                print("❌  ID: --id <id>")
                sys.exit(1)
            cli.deny(args.id, args.reason)
    
    elif args.command == "init":
        cli.init()
    
    elif args.command == "version":
        from clawguard import __version__
        print(f"ClawGuard v{__version__}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()