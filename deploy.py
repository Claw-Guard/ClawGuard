#!/usr/bin/env python3
"""Install, configure, and start the standalone ClawGuard API gateway.

This script deploys ClawGuard only. Codex, OpenClaw, and other Agent runtimes
must be installed and configured separately by their users.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


AGENT_PROTOCOLS = {
    "codex": ("responses",),
    "openclaw": ("responses", "chat-completions"),
    "claude": ("anthropic-messages",),
}
PROTOCOL_FORMAT = {
    "responses": ("openai_response", True),
    "chat-completions": ("openai_chat_completion", False),
    "anthropic-messages": ("anthropic_message", False),
}


def run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> str:
    print("+", " ".join(args))
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if result.returncode != 0:
        detail = ""
        if capture:
            detail = f"\n{(result.stdout or '').strip()}\n{(result.stderr or '').strip()}".rstrip()
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(args)}{detail}")
    return result.stdout or ""


def configure_python(repo: Path, *, no_install: bool) -> Path:
    if no_install:
        python = Path(sys.executable)
    else:
        venv_dir = repo / ".venv"
        if os.name == "nt":
            python = venv_dir / "Scripts" / "python.exe"
        else:
            python = venv_dir / "bin" / "python"
        if not python.exists():
            run([sys.executable, "-m", "venv", str(venv_dir)], cwd=repo)
        check = subprocess.run(
            [
                str(python),
                "-c",
                "import fastapi,httpx,uvicorn,yaml; import clawguard",
            ],
            cwd=repo,
            text=True,
            capture_output=True,
        )
        if check.returncode != 0:
            run(
                [str(python), "-m", "pip", "install", "--upgrade", "pip"],
                cwd=repo,
            )
            run([str(python), "-m", "pip", "install", "-e", "."], cwd=repo)
    return python


def seed_and_configure(
    python: Path,
    repo: Path,
    config_dir: Path,
    *,
    agent: str,
    protocol: str,
    upstream_url: str | None,
    host: str,
    port: int,
    reset_config: bool,
) -> tuple[Path, Path, str]:
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    rules_path = config_dir / "rules.yaml"
    if reset_config or not config_path.exists():
        shutil.copy2(repo / "config" / "config.yaml", config_path)
    if reset_config or not rules_path.exists():
        shutil.copy2(repo / "config" / "rules.yaml", rules_path)

    upstream_format, responses_enabled = PROTOCOL_FORMAT[protocol]
    upstream_assignment = (
        'gateway.setdefault("upstream_base_url", "https://api.deepseek.com")'
        if upstream_url is None
        else f"gateway['upstream_base_url'] = {upstream_url!r}"
    )
    patch_code = f"""
from pathlib import Path
import yaml

path = Path({str(config_path)!r})
data = yaml.safe_load(path.read_text(encoding="utf-8")) or {{}}
gateway = data.setdefault("gateway", {{}})
gateway["host"] = {host!r}
gateway["port"] = {port}
gateway["agent"] = {agent!r}
gateway["upstream_format"] = {upstream_format!r}
gateway["enable_responses_api"] = {responses_enabled!r}
{upstream_assignment}
gateway["forward_client_authorization"] = True
gateway["policy_mode"] = "supervised"
gateway.pop("upstream_api_key", None)
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
"""
    run([str(python), "-c", patch_code], cwd=repo)
    read_url = (
        "from pathlib import Path; import yaml; "
        f"d=yaml.safe_load(Path({str(config_path)!r}).read_text(encoding='utf-8')); "
        "print(d['gateway']['upstream_base_url'])"
    )
    effective_upstream = run([str(python), "-c", read_url], cwd=repo, capture=True).strip()
    return config_path, rules_path, effective_upstream


def status(host: str, port: int, timeout: float = 2.0) -> dict | None:
    try:
        with urllib.request.urlopen(
            f"http://{host}:{port}/status", timeout=timeout
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None


def read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def stop_gateway(pid_path: Path) -> int:
    pid = read_pid(pid_path)
    if pid is None:
        print("ClawGuard is not running (no PID file).")
        return 0
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                raise OSError((result.stderr or result.stdout).strip())
        else:
            os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"Could not stop PID {pid}: {exc}")
        print(f"Remove stale PID file if needed: {pid_path}")
        return 1
    pid_path.unlink(missing_ok=True)
    print(f"ClawGuard stopped (PID {pid}).")
    return 0


def wait_until_ready(
    process: subprocess.Popen | None, host: str, port: int, log_path: Path
) -> dict:
    deadline = time.time() + 90
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            tail = ""
            if log_path.exists():
                tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-30:])
            raise RuntimeError(
                f"ClawGuard exited with code {process.returncode}."
                + (f"\n{tail}" if tail else "")
            )
        value = status(host, port)
        if value is not None:
            return value
        time.sleep(1)
    raise RuntimeError("ClawGuard did not become ready within 90 seconds.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install and run ClawGuard only. The selected Agent runtime "
            "(Codex, OpenClaw, or Claude) must be installed separately."
        )
    )
    parser.add_argument("--agent", choices=sorted(AGENT_PROTOCOLS), default="codex")
    parser.add_argument(
        "--protocol",
        choices=sorted(PROTOCOL_FORMAT),
        default="responses",
        help="Provider API protocol used by the selected Agent.",
    )
    parser.add_argument(
        "--upstream-url",
        default=None,
        help=(
            "Provider API origin that ClawGuard forwards accepted requests to. "
            "If omitted, keep the existing value or default to DeepSeek."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19822)
    parser.add_argument(
        "--config-dir",
        default=str(Path.home() / ".clawguard"),
        help="Runtime configuration and state directory.",
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Use the current Python environment instead of creating .venv.",
    )
    parser.add_argument(
        "--foreground",
        action="store_true",
        help="Keep the gateway attached to this terminal.",
    )
    parser.add_argument("--reset-config", action="store_true")
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Install dependencies and write configuration without starting.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.protocol not in AGENT_PROTOCOLS[args.agent]:
        allowed = ", ".join(AGENT_PROTOCOLS[args.agent])
        raise SystemExit(
            f"Agent {args.agent!r} supports: {allowed}; got {args.protocol!r}"
        )

    repo = Path(__file__).resolve().parent
    config_dir = Path(args.config_dir).expanduser().resolve()
    pid_path = config_dir / "gateway.pid"

    if args.status:
        value = status(args.host, args.port)
        if value is None:
            print("ClawGuard is not running.")
            return 1
        print(json.dumps(value, indent=2))
        return 0
    if args.stop:
        return stop_gateway(pid_path)

    existing = status(args.host, args.port)
    if existing is not None and not args.restart:
        expected_format = PROTOCOL_FORMAT[args.protocol][0]
        if (
            existing.get("agent") == args.agent
            and existing.get("upstream_format") == expected_format
        ):
            print(
                f"ClawGuard is already running at http://{args.host}:{args.port} "
                f"({args.agent}/{args.protocol})."
            )
            return 0
        raise SystemExit(
            "A ClawGuard gateway is already running with different settings. "
            "Rerun with --restart to replace it."
        )
    if args.restart:
        if existing is not None and not pid_path.exists():
            raise SystemExit(
                "A gateway is listening but it was not started by this script "
                f"(missing PID file {pid_path}). Stop it manually."
            )
        if pid_path.exists():
            code = stop_gateway(pid_path)
            if code:
                return code
            time.sleep(1)

    python = configure_python(repo, no_install=args.no_install)
    config_path, rules_path, effective_upstream = seed_and_configure(
        python,
        repo,
        config_dir,
        agent=args.agent,
        protocol=args.protocol,
        upstream_url=args.upstream_url,
        host=args.host,
        port=args.port,
        reset_config=args.reset_config,
    )
    if args.prepare_only:
        print(f"ClawGuard prepared. Config: {config_path}")
        print(f"Rules: {rules_path}")
        print("Start with the same command without --prepare-only.")
        return 0

    upstream_format, responses_enabled = PROTOCOL_FORMAT[args.protocol]
    child_env = os.environ.copy()
    child_env.update(
        {
            "CLAWGUARD_CONFIG": str(config_path),
            "CLAWGUARD_RULES": str(rules_path),
            "CLAWGUARD_AGENT": args.agent,
            "CLAWGUARD_UPSTREAM_FORMAT": upstream_format,
            "CLAWGUARD_ENABLE_RESPONSES_API": str(responses_enabled).lower(),
            "CLAWGUARD_UPSTREAM_BASE_URL": effective_upstream,
            "CLAWGUARD_GATEWAY_HOST": args.host,
            "CLAWGUARD_GATEWAY_PORT": str(args.port),
            "CLAWGUARD_FORWARD_CLIENT_AUTHORIZATION": "true",
        }
    )
    command = [str(python), "-m", "clawguard.gateway"]

    if args.foreground:
        print(
            f"Starting ClawGuard at http://{args.host}:{args.port} "
            f"for {args.agent}/{args.protocol} -> {effective_upstream}. "
            "Press Ctrl+C to stop."
        )
        try:
            return subprocess.run(command, cwd=repo, env=child_env).returncode
        except KeyboardInterrupt:
            return 0

    log_dir = config_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "gateway.log"
    log_handle = log_path.open("a", encoding="utf-8")
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    process = subprocess.Popen(
        command,
        cwd=repo,
        env=child_env,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=os.name != "nt",
        creationflags=creationflags,
    )
    pid_path.write_text(str(process.pid), encoding="utf-8")
    try:
        current = wait_until_ready(process, args.host, args.port, log_path)
    finally:
        log_handle.close()

    print(
        f"ClawGuard is ready at http://{args.host}:{args.port}\n"
        f"  PID:     {process.pid}\n"
        f"  Agent:   {current.get('agent')}\n"
        f"  Format:  {current.get('upstream_format')}\n"
        f"  Upstream: {effective_upstream}\n"
        f"  Config:  {config_path}\n"
        f"  Log:     {log_path}\n"
        "\nThe Agent runtime was not installed or configured by this script."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
