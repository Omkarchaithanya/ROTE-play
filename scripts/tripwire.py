#!/usr/bin/env python3
"""TRIPWIRE AgentOps Control Layer.

A local-first, read-only Agent Surface Census that builds an Agent Permission Graph,
calculates Blast Radius, detects schema drift, and generates an AgentOps "git diff".
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import getpass
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|password|passwd|credential|credentials|cookie|bearer|oauth|(^|[_\-.])token($|[_\-.])|(^|[_\-.])secret($|[_\-.]))",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(r"^(|changeme|change-me|todo|example|xxx+|your[_-]?.+|<.+>)$", re.IGNORECASE)

ACTION_READ_ONLY = "READ_ONLY"
ACTION_EXTERNAL_WRITE = "EXTERNAL_WRITE"
ACTION_MACHINE_MUTATION = "MACHINE_MUTATION"
ACTION_LOCAL_STATE_WRITE = "LOCAL_STATE_WRITE"
ACTION_CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
ACTION_UNKNOWN = "UNKNOWN"

@dataclass
class Finding:
    probe: str
    name: str
    status: str = "ok"
    severity: str = "S0"
    message: str = ""
    path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
class Finding(dict):
    def __init__(self, probe: str, name: str, status: str, severity: str, message: str,
                 path: str = "", details: dict[str, Any] | None = None, **kwargs):
        super().__init__()
        self["id"] = f"{probe}_{name}_{hashlib.md5(message.encode()).hexdigest()[:8]}"
        self["probe"] = probe
        self["name"] = name
        self["status"] = status
        self["severity"] = severity
        self["message"] = message
        self["path"] = path
        self["details"] = details or {}
        self["evidence"] = kwargs.pop("evidence", message)
        self["evidence_type"] = kwargs.pop("evidence_type", "OBSERVED")
        self["confidence"] = kwargs.pop("confidence", "HIGH")
        self["claim"] = kwargs.pop("claim", message)
        self["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self["source"] = probe
        for k, v in kwargs.items(): self[k] = v

    def as_dict(self) -> dict[str, Any]:
        return self

def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if str(key) in {"credential", "credential_keys", "credentials", "write_contract"}:
                cleaned[str(key)] = scrub(item)
            elif SECRET_NAME_RE.search(str(key)):
                cleaned[str(key)] = credential_state(item)
            else:
                cleaned[str(key)] = scrub(item)
        return cleaned
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        if SECRET_VALUE_RE.search(value):
            return "NEVER DISPLAYED"
        return value
    return value

def credential_state(value: Any) -> str:
    if value is None: return "MISSING"
    text = str(value).strip()
    if PLACEHOLDER_RE.match(text): return "PLACEHOLDER"
    return "PRESENT"

def credential_locus_name(name: str) -> bool:
    lowered = name.lower()
    return (lowered.startswith(".env") or lowered in {"auth.json", "credentials.json", "credential.json", "secrets.json", "secret.json"} or SECRET_NAME_RE.search(name) is not None)

def credential_artifact_name(name: str) -> bool:
    lowered = name.lower()
    normalized = lowered.lstrip(".")
    return (lowered.startswith(".env") or normalized in {"auth.json", "credentials.json", "credential.json", "secrets.json", "secret.json"} or lowered.endswith((".pem", ".key", ".p12", ".pfx", ".token")))

def emit(probe: str, findings: list[Finding], warnings: list[str] | None = None, **extra: Any) -> int:
    payload = {"ok": True, "probe": probe, "warnings": warnings or [], "findings": [item.as_dict() for item in findings]}
    payload.update({key: scrub(value) for key, value in extra.items()})
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0

def payload(probe: str, findings: list[Finding], warnings: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    out = {"ok": True, "probe": probe, "warnings": warnings or [], "findings": [item.as_dict() for item in findings]}
    out.update({key: scrub(value) for key, value in extra.items()})
    return out

def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home()).expanduser()

def workspace() -> Path:
    return Path(os.environ.get("TRIPWIRE_WORKSPACE") or os.getcwd()).resolve()

def configure_demo(enabled: bool) -> None:
    if not enabled:
        for key in ("TRIPWIRE_HOME", "TRIPWIRE_WORKSPACE"):
            value = os.environ.get(key, "").replace("\\", "/").lower()
            if "/tests/fixtures/demo/" in value:
                os.environ.pop(key, None)
        os.environ.pop("TRIPWIRE_DEMO_ACTIVE", None)
        return
    root = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "demo"
    os.environ["TRIPWIRE_HOME"] = str(root / "home")
    os.environ["TRIPWIRE_WORKSPACE"] = str(root / "workspace")
    os.environ["TRIPWIRE_DEMO_ACTIVE"] = "1"

def demo_active() -> bool:
    return os.environ.get("TRIPWIRE_DEMO_ACTIVE") == "1"

def excluded_path(path: Path) -> bool:
    if demo_active(): return False
    normalized = safe_path(path).replace("\\", "/").lower()
    return "/tests/fixtures/" in normalized

def safe_path(path: Path) -> str:
    try: return str(path.expanduser().resolve())
    except OSError: return str(path.expanduser())

def exists(path: Path) -> bool:
    try: return path.exists()
    except (OSError, PermissionError): return True

def can_read(path: Path) -> bool:
    try:
        if path.is_file():
            with path.open("rb") as handle: handle.read(1)
        elif path.is_dir(): next(path.iterdir(), None)
        return True
    except (OSError, PermissionError): return False

def run_cmd(argv: list[str], timeout: int = 5) -> tuple[bool, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        text = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode == 0, text
    except (OSError, subprocess.SubprocessError): return False, ""

def command_version(command: str, args: list[str] | None = None) -> tuple[bool, str]:
    exe = shutil.which(command)
    if not exe: return False, "NOT INSTALLED"
    ok, text = run_cmd([exe] + (args or ["--version"]))
    first_line = text.splitlines()[0] if text else ""
    return True, first_line if ok and first_line else "installed, version unknown"

def want(scope: str, probe: str) -> bool:
    groups = {
        "harness": {"harness_inventory", "agent_identity"},
        "mcp": {"mcp_census"},
        "plays": {"play_registry"},
        "secrets": {"secret_loci", "git_leak_probe"},
        "network": {"listen_surface", "network_surface"},
        "filesystem": {"filesystem_reachability"},
        "all": {"harness_inventory", "agent_identity", "mcp_census", "play_registry", "secret_loci", "token_ttl", "listen_surface", "price_tape", "git_leak_probe", "filesystem_reachability", "network_surface"}
    }
    return probe in groups.get(scope, groups["all"])

def skipped(probe: str, scope: str) -> int:
    return emit(probe, [Finding(probe, probe, "skipped", "UNKNOWN", f"skipped by scope={scope}", evidence_type="parameter gate", confidence="HIGH")])

def run_probe_payload(func: Any, args: argparse.Namespace) -> dict[str, Any]:
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream): func(args)
    try: return json.loads(stream.getvalue())
    except json.JSONDecodeError: return {"ok": False, "probe": getattr(func, "__name__", "unknown"), "warnings": ["invalid json"], "findings": []}

# --- PROBES ---

def agent_identity(args: argparse.Namespace) -> int:
    probe = "agent_identity"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    user = getpass.getuser()
    findings.append(Finding(probe, "os_user", "ok", "S0", "local OS identity", details={"user": user, "os": platform.system()}))
    
    git = shutil.which("git")
    if git:
        ok, email = run_cmd([git, "config", "user.email"])
        if ok and email:
            findings.append(Finding(probe, "git_identity", "ok", "S0", "git identity configured", details={"email": email}))
            
    ssh_dir = home() / ".ssh"
    if exists(ssh_dir) and can_read(ssh_dir):
        keys = [p.name for p in ssh_dir.glob("id_*") if p.is_file() and not p.name.endswith(".pub")]
        findings.append(Finding(probe, "ssh_identity", "ok", "S0", f"{len(keys)} SSH identities detected", details={"count": len(keys)}))
        
    return emit(probe, findings)

def filesystem_reachability(args: argparse.Namespace) -> int:
    probe = "filesystem_reachability"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    h = home()
    paths = [workspace(), h / ".ssh", h / ".aws", h / ".config", h / "Documents", h / "projects"]
    for p in paths:
        if exists(p) and can_read(p):
            can_write = os.access(p, os.W_OK)
            sev = "S2" if p.name in {".ssh", ".aws", ".config"} else "S0"
            findings.append(Finding(probe, p.name, "ok", sev, "Path reachable", path=str(p), details={"read": True, "write": can_write}))
    return emit(probe, findings)

def network_surface(args: argparse.Namespace) -> int:
    probe = "network_surface"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    
    ok, text = run_cmd(["netstat", "-ano"], timeout=8)
    if not ok and not text:
        ok, text = run_cmd(["ss", "-tnp"], timeout=8)
        
    if not text:
        findings.append(Finding(probe, "endpoints", "unknown", "UNKNOWN", "network inspection unavailable"))
        return emit(probe, findings)
        
    endpoints = set()
    for line in text.splitlines():
        if "ESTABLISHED" in line.upper():
            parts = line.split()
            for p in parts:
                if ":" in p and not p.startswith("["):
                    ip = p.split(":")[0]
                    if ip.count(".") == 3 and ip not in ("127.0.0.1", "0.0.0.0"):
                        endpoints.add(ip)
                        
    if endpoints:
        findings.append(Finding(probe, "endpoints", "ok", "S1", "Reachable endpoints inferred", details={"endpoints": sorted(list(endpoints))[:20]}))
    else:
        findings.append(Finding(probe, "endpoints", "ok", "S0", "No active external endpoints inferred"))
        
    return emit(probe, findings)

def harness_inventory(args: argparse.Namespace) -> int:
    probe = "harness_inventory"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    h = home()
    specs = [
        ("Claude", ["claude"], [h / ".claude.json", h / ".claude"]),
        ("Cursor", ["cursor"], [h / ".cursor", h / "AppData/Roaming/Cursor/User"]),
        ("Codex", ["codex"], [h / ".codex", h / ".codex/config.toml"]),
        ("Kimi", ["kimi"], [h / ".kimi", h / ".config/kimi"]),
    ]
    findings = []
    for label, commands, paths in specs:
        installed = False
        version = "NOT INSTALLED"
        for command in commands:
            installed, version = command_version(command)
            if installed: break
        readable_paths = [safe_path(path) for path in paths if exists(path) and can_read(path)]
        status = "ok" if installed or readable_paths else "missing"
        severity = "S1" if readable_paths and not installed else "S0"
        message = "harness detected" if status == "ok" else "harness not installed"
        findings.append(Finding(probe, label, status, severity, message, details={"version": version, "config_locations": readable_paths or ["unknown"]}))
    return emit(probe, findings, host={"os": platform.platform(), "python": sys.version.split()[0]})

def infer_tool_capability(server_name: str, tool: dict) -> str:
    name = (tool.get("name") or "").lower().replace("_", " ").replace("-", " ")
    desc = (tool.get("description") or "").lower().replace("_", " ").replace("-", " ")
    
    write_keywords = [r"\bwrite\b", r"\bupdate\b", r"\bdelete\b", r"\bcreate\b", r"\bexecute\b", r"\brun\b", r"\bapply\b", r"\bdeploy\b", r"\bmutation\b", r"\bmodify\b"]
    read_keywords = [r"\bread\b", r"\bget\b", r"\blist\b", r"\bfetch\b", r"\bsearch\b", r"\bquery\b", r"\bcheck\b", r"\binfo\b", r"\bstatus\b"]
    
    def matches(keywords):
        for k in keywords:
            if re.search(k, name) or re.search(k, desc): return True
        return False
        
    is_write = matches(write_keywords)
    is_read = matches(read_keywords)
    
    if is_write and is_read: return ACTION_UNKNOWN
    if is_write:
        server_lower = server_name.lower()
        if any(w in server_lower for w in ["filesystem", "bash", "cmd", "shell", "os", "file"]):
            return ACTION_MACHINE_MUTATION
        elif any(w in server_lower for w in ["memory", "sqlite"]):
            return ACTION_LOCAL_STATE_WRITE
        return ACTION_EXTERNAL_WRITE
        
    if is_read:
        return ACTION_READ_ONLY
        
    return ACTION_UNKNOWN

def find_keys(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    hits = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            if SECRET_NAME_RE.search(str(key)) and isinstance(value, str):
                hits.append((full, credential_state(value)))
            hits.extend(find_keys(value, full))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            hits.extend(find_keys(value, f"{prefix}[{idx}]"))
    return hits

def canonicalize_tools(tools: list[dict]) -> str:
    canonical = []
    for t in tools:
        c = {
            "name": t.get("name", ""),
            "description": t.get("description", ""),
            "inputSchema": t.get("inputSchema", {}),
        }
        if "outputSchema" in t: c["outputSchema"] = t["outputSchema"]
        canonical.append(c)
    return json.dumps(canonical, sort_keys=True)

def fetch_mcp_tools(command: str, args: list[str]) -> tuple[list[dict], str]:
    if demo_active(): return [], "sha256:demo"
    try:
        proc = subprocess.Popen([command] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        proc.stdin.write(req + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        proc.terminate()
        if line:
            resp = json.loads(line)
            tools = resp.get("result", {}).get("tools", [])
            schema_str = canonicalize_tools(tools)
            return tools, "sha256:" + hashlib.sha256(schema_str.encode("utf-8")).hexdigest()[:16]
    except Exception: pass
    return [], "UNKNOWN"

def mcp_census(args: argparse.Namespace) -> int:
    probe = "mcp_census"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    h = home()
    candidates = [h / ".cursor/mcp.json", h / ".claude.json", h / ".codex/config.toml", workspace() / ".mcp.json"]
    findings = []
    warnings = []
    for path in candidates:
        if not exists(path): continue
        if not can_read(path):
            findings.append(Finding(probe, path.name, "unknown", "UNKNOWN", "unreadable", safe_path(path)))
            continue
        detail = {"credential_keys": [], "server_names": [], "transport": "UNKNOWN", "tools_fingerprint": {}}
        try:
            if path.suffix.lower() == ".json" or path.name.endswith(".json"):
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                detail["credential_keys"] = [{"key": k, "credential": s} for k, s in find_keys(data)]
                servers = data.get("mcpServers") if isinstance(data, dict) else None
                write_caps = []
                if isinstance(servers, dict):
                    detail["server_names"] = sorted(str(n) for n in servers.keys())
                    for server_name, cfg in servers.items():
                        tools = []
                        if isinstance(cfg, dict):
                            cmd = cfg.get("command")
                            args_list = cfg.get("args", [])
                            if cmd:
                                tools, fingerprint = fetch_mcp_tools(cmd, args_list)
                                detail["tools_fingerprint"][str(server_name)] = {"tool_count": len(tools), "fingerprint": fingerprint, "tools": [t.get("name") for t in tools]}
                        if tools:
                            for t in tools:
                                cap = infer_tool_capability(str(server_name), t)
                                write_caps.append({"server": str(server_name), "tool": t.get("name"), "write_capability": cap})
                        else:
                            write_caps.append({"server": str(server_name), "tool": None, "write_capability": ACTION_UNKNOWN})
                detail["write_capabilities"] = write_caps
        except Exception as exc: warnings.append(f"{safe_path(path)} parse failed: {exc.__class__.__name__}")
        has_write = any(item.get("write_capability") in (ACTION_EXTERNAL_WRITE, ACTION_MACHINE_MUTATION, ACTION_LOCAL_STATE_WRITE) for item in detail.get("write_capabilities", []))
        sev = "S2" if detail["credential_keys"] else ("S3" if has_write else "S1")
        msg = "credential metadata present" if detail["credential_keys"] else "MCP configuration present"
        findings.append(Finding(probe, path.name, "ok", sev, msg, safe_path(path), detail, surface="mcp", credential_state="PRESENT" if detail["credential_keys"] else "UNKNOWN", write_capability="POTENTIAL" if has_write else "UNKNOWN", confidence="HIGH", evidence="Parsed MCP configuration file."))
    if not findings: findings.append(Finding(probe, "mcp config", "missing", "S0", "no MCP configuration found"))
    return emit(probe, findings, warnings)

def bounded_files() -> Iterable[Path]:
    h = home()
    names = [".env", ".env.local", ".envrc", "mcp.json", ".mcp.json", "claude_desktop_config.json"]
    roots = [workspace(), h / ".config", h / ".codex", h / ".claude", h / ".cursor"]
    for root in roots:
        if not exists(root) or not can_read(root):
            yield root
            continue
        for name in names:
            if exists(root / name): yield root / name
        try:
            for path in list(root.rglob("*"))[:500]:
                if excluded_path(path): continue
                if path.is_file() and (path.name in names or credential_locus_name(path.name)): yield path
        except (OSError, PermissionError): yield root

def secret_loci(args: argparse.Namespace) -> int:
    probe = "secret_loci"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    seen = set()
    for path in bounded_files():
        key = safe_path(path)
        if key in seen: continue
        seen.add(key)
        if not exists(path): continue
        if not can_read(path):
            findings.append(Finding(probe, path.name, "unknown", "UNKNOWN", "path unreadable", key))
            continue
        if path.is_dir(): continue
        try:
            content = path.read_text(errors='ignore')
            keys = find_keys(content)
            
            is_code_file = path.suffix in [".py", ".ts", ".js", ".go", ".rs", ".java", ".cpp", ".c", ".h"]
            
            if keys:
                detail = {"type": "credential material", "presence": "PRESENT", "contents": "NEVER DISPLAYED", "exposed_keys": [k for k, _ in keys], "agent_usable": "UNKNOWN"}
                findings.append(Finding(probe, path.name, "ok", "S2", "credential material present", key, detail, surface="filesystem", credential_state="PRESENT", confidence="HIGH", evidence="Found secret keys in file"))
            elif credential_artifact_name(path.name):
                findings.append(Finding(probe, path.name, "ok", "S2", "credential-related artifact", key, {"type": "credential artifact", "presence": "PRESENT", "contents": "NEVER DISPLAYED", "agent_usable": "UNKNOWN"}, surface="filesystem", credential_state="PRESENT", confidence="MEDIUM", evidence="File matches known high-risk credential filenames"))
            elif credential_locus_name(path.name):
                sev = "S1" if not is_code_file else "S0"
                findings.append(Finding(probe, path.name, "ok", sev, "credential-related filename", key, {"type": "credential-shaped file", "presence": "PRESENT", "contents": "NEVER DISPLAYED", "agent_usable": "UNKNOWN"}, surface="filesystem", credential_state="PRESENT", confidence="MEDIUM", evidence="Filename matches credential patterns but no material found"))
        except Exception:
            findings.append(Finding(probe, path.name, "unknown", "UNKNOWN", "unreadable", key, confidence="LOW"))
    if not findings: findings.append(Finding(probe, "secrets", "missing", "S0", "no credential loci found"))
    return emit(probe, findings)

def play_registry(args: argparse.Namespace) -> int:
    probe = "play_registry"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    h = home()
    roots = [h / ".rote/play", h / ".rote/plays", h / ".rote-play", workspace()]
    findings = []
    for root in roots:
        if not exists(root): continue
        if not can_read(root):
            findings.append(Finding(probe, root.name, "unknown", "UNKNOWN", "unreadable", safe_path(root)))
            continue
        try:
            for path in list(root.rglob("main.ts"))[:100]:
                if excluded_path(path): continue
                text = path.read_text(encoding="utf-8", errors="replace")
                declares_write = "write" in text.lower() or "apply" in text.lower()
                readonly_claim = "read-only" in text.lower() or "readonly" in text.lower()
                disabled_write_contract = "revoke_stale is declared but disabled" in text or "revoke_stale: DISABLED" in text
                mismatch = readonly_claim and not disabled_write_contract and re.search(r"\b(delete|remove|revoke|write|set-content|rm)\b", text, re.I)
                findings.append(Finding(probe, path.parent.name, "ok", "S3" if mismatch else ("S1" if declares_write else "S0"), "possible read-only/write mismatch" if mismatch else "play metadata inspected", safe_path(path), {"write_capability": "POTENTIAL" if declares_write else "UNKNOWN", "readonly_claim": readonly_claim}, surface="rote_play", write_capability="POTENTIAL" if declares_write else "UNKNOWN", confidence="medium" if declares_write else "high"))
        except Exception as exc: findings.append(Finding(probe, root.name, "unknown", "UNKNOWN", exc.__class__.__name__, safe_path(root)))
    if not findings: findings.append(Finding(probe, "local plays", "missing", "S0", "no local plays"))
    return emit(probe, findings)

def token_ttl(args: argparse.Namespace) -> int:
    probe = "token_ttl"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    gh = shutil.which("gh")
    if gh:
        ok, text = run_cmd([gh, "auth", "status"], timeout=8)
        findings.append(Finding(probe, "GitHub CLI", "ok" if ok else "unknown", "S1", "expiry: UNKNOWN", details={"installed": True, "auth_status": "available" if ok else "UNKNOWN", "output": scrub(text)}))
    else:
        findings.append(Finding(probe, "GitHub CLI", "missing", "S0", "gh: NOT INSTALLED"))
    ssh_dir = home() / ".ssh"
    if exists(ssh_dir) and can_read(ssh_dir):
        for key_path in list(ssh_dir.glob("id_*"))[:20]:
            if key_path.is_file() and not key_path.name.endswith(".pub"):
                age_days = int((time.time() - key_path.stat().st_mtime) / 86400)
                findings.append(Finding(probe, key_path.name, "ok", "S1" if age_days > 365 else "S0", "ssh key metadata present", safe_path(key_path), {"age_days": age_days, "expiry": "UNKNOWN"}))
    return emit(probe, findings)

def listen_surface(args: argparse.Namespace) -> int:
    probe = "listen_surface"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    warnings = []
    commands = [["netstat", "-ano"], ["ss", "-ltnp"], ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"]]
    text = ""
    for cmd in commands:
        if shutil.which(cmd[0]):
            ok, text = run_cmd(cmd, timeout=8)
            if ok or text: break
    if not text:
        warnings.append("listener inspection unavailable")
        findings.append(Finding(probe, "listeners", "unknown", "UNKNOWN", "listener permission failure"))
    else:
        local_lines = [line for line in text.splitlines() if "LISTEN" in line.upper() or "127.0.0.1" in line or "0.0.0.0" in line]
        suspicious = [line for line in local_lines if any(term in line.lower() for term in ["mcp", "claude", "cursor", "codex", "node"])]
        severity = "S1" if suspicious else "S0"
        findings.append(Finding(probe, "local listeners", "ok", severity, "listener metadata collected", details={"listener_count": len(local_lines), "agent_related_count": len(suspicious), "values": "redacted"}))
    return emit(probe, findings, warnings)

def price_tape(args: argparse.Namespace) -> int:
    probe = "price_tape"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    url = os.environ.get("TRIPWIRE_PRICE_URL", "https://www.modiqo.ai/pricing")
    findings = []
    warnings = []
    try:
        req = Request(url, headers={"User-Agent": "tripwire/0.1"})
        with urlopen(req, timeout=8) as response: status = getattr(response, "status", 0)
        findings.append(Finding(probe, "pricing", "ok", "S0", "pricing source reachable", details={"source": url, "http_status": status}))
    except (OSError, URLError, TimeoutError) as exc:
        warnings.append(f"pricing: UNKNOWN ({exc.__class__.__name__})")
        findings.append(Finding(probe, "pricing", "unknown", "UNKNOWN", "pricing: UNKNOWN", details={"source": url}))
    return emit(probe, findings, warnings)

def git_leak_probe(args: argparse.Namespace) -> int:
    probe = "git_leak_probe"
    if not want(args.scope, probe): return skipped(probe, args.scope)
    findings = []
    
    if not shutil.which("git"):
        findings.append(Finding(probe, "git_binary", "unknown", "UNKNOWN", "git history unavailable", confidence="LOW", evidence="shutil.which('git') failed"))
        return emit(probe, findings)
    
    repo = workspace()
    ok, out = run_cmd(["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"], timeout=5)
    if not ok or "true" not in out.lower():
        findings.append(Finding(probe, "git_repo", "unknown", "UNKNOWN", "not a git repository", confidence="LOW", evidence="git rev-parse failed"))
        return emit(probe, findings)
    
    ok, text = run_cmd(["git", "-C", str(repo), "log", "-n", "10", "--name-only", "--pretty=format:"], timeout=10)
    if not ok:
        findings.append(Finding(probe, "git_history", "unknown", "UNKNOWN", "git log failed", confidence="LOW", evidence="git log command failed"))
        return emit(probe, findings)
        
    paths = sorted({line.strip() for line in text.splitlines() if line.strip()})
    risky = [path for path in paths if credential_locus_name(Path(path).name) or ".mcp" in path.lower()]
    if risky: findings.append(Finding(probe, "recent git history", "ok", "S2", "credential-shaped paths found in recent commits", details={"paths": risky[:50], "truncated": len(risky) > 50}))
    else: findings.append(Finding(probe, "recent git history", "ok", "S0", "no credential-shaped paths found in recent commits"))
    return emit(probe, findings)

# --- LAYER 2: NORMALIZATION & DELTA ---

def load_payloads(values: list[str]) -> list[dict[str, Any]]:
    payloads = []
    for value in values:
        try: payloads.append(json.loads(value))
        except json.JSONDecodeError: payloads.append({"ok": False, "probe": "unknown", "warnings": ["invalid json"], "findings": []})
    return payloads

def hash_state(state: dict) -> str:
    s = {k: v for k, v in state.items() if k not in ("hash", "timestamp")}
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode("utf-8")).hexdigest()

def analyze_payloads(payloads: list[dict[str, Any]], update_baseline: bool = False) -> dict[str, Any]:
    all_findings = [f for p in payloads for f in p.get("findings", [])]
    
    # 1. Agent Permission Graph Extraction
    graph = []
    harnesses = [f.get("name", "UNKNOWN") for f in all_findings if f.get("probe") == "harness_inventory" and f.get("status") == "ok"]
    active_agent = harnesses[0] if harnesses else "UNKNOWN_AGENT"
    
    for f in all_findings:
        if f.get("probe") == "mcp_census" and f.get("status") == "ok":
            write_caps = f.get("details", {}).get("write_capabilities", [])
            for w in write_caps:
                s = w.get("server", "unknown")
                t = w.get("tool")
                cap = w.get("write_capability", ACTION_UNKNOWN)
                
                if t:
                    evidence_type = "OBSERVED"
                    confidence = "HIGH"
                else:
                    evidence_type = "INFERRED"
                    confidence = "LOW"
                    
                sev = "S3" if cap in (ACTION_EXTERNAL_WRITE, ACTION_MACHINE_MUTATION, ACTION_LOCAL_STATE_WRITE) else ("S0" if cap == ACTION_READ_ONLY else "UNKNOWN")
                
                graph.append({
                    "agent": active_agent,
                    "harness": active_agent.lower(),
                    "tool_mcp": s,
                    "tool_name": t,
                    "resource": "local/remote",
                    "effect": cap,
                    "evidence_type": evidence_type,
                    "confidence": confidence,
                    "severity": sev
                })
    
    # 4. Blast Radius (0-100)
    blast_score = 0
    blast_contributors = []
    
    cred_count = sum(1 for f in all_findings if f.get("probe") == "secret_loci" and f.get("status") == "ok" and f.get("severity") == "S2")
    if cred_count > 0:
        blast_score += 20
        blast_contributors.append("Credential access/exposure: +20")
        
    has_external_write = any(w.get("write_capability") == ACTION_EXTERNAL_WRITE for f in all_findings for w in f.get("details", {}).get("write_capabilities", []))
    if has_external_write:
        blast_score += 20
        blast_contributors.append("External write capability: +20")
        
    has_machine_mutation = any(w.get("write_capability") == ACTION_MACHINE_MUTATION for f in all_findings for w in f.get("details", {}).get("write_capabilities", []))
    if has_machine_mutation:
        blast_score += 15
        blast_contributors.append("Machine mutation capability: +15")
        
    fs_reachable = any(f.get("probe") == "filesystem_reachability" and f.get("status") == "ok" for f in all_findings)
    if fs_reachable:
        blast_score += 12
        blast_contributors.append("Filesystem reachability (sensitive): +12")
        
    net_reachable = any(f.get("probe") == "network_surface" and f.get("status") == "ok" for f in all_findings)
    if net_reachable:
        blast_score += 10
        blast_contributors.append("Network reachability: +10")
        
    total_tools = sum(f.get("details", {}).get("tools_fingerprint", {}).get(s, {}).get("tool_count", 0) for f in all_findings if f.get("probe") == "mcp_census" for s in f.get("details", {}).get("server_names", []))
    if total_tools >= 10:
        blast_score += 10
        blast_contributors.append("Tool breadth (>= 10 tools): +10")
        
    blast_score = min(100, blast_score)
    if blast_score < 25: risk_band = "LOW"
    elif blast_score < 50: risk_band = "MEDIUM"
    elif blast_score < 75: risk_band = "HIGH"
    else: risk_band = "CRITICAL"
            
    # 2. Baseline state extraction
    prev_baseline_path = workspace() / ".tripwire_previous.json"
    appr_baseline_path = workspace() / ".tripwire_approved.json"
    
    current_state = {
        "version": "1.0",
        "schema_version": "1.0",
        "mcp_schemas": {},
        "mcp_count": len([f for f in all_findings if f.get("probe") == "mcp_census"]),
        "cred_count": len([f for f in all_findings if f.get("probe") == "secret_loci"]),
        "external_write_count": sum(1 for f in all_findings if f.get("probe") == "mcp_census" for cap in f.get("details", {}).get("write_capabilities", []) if cap.get("write_capability") == ACTION_EXTERNAL_WRITE)
    }
    
    for f in all_findings:
        if f.get("probe") == "mcp_census" and "tools_fingerprint" in f.get("details", {}):
            for srv, fp in f["details"]["tools_fingerprint"].items():
                current_state["mcp_schemas"][srv] = fp["fingerprint"]
                
    # Load baselines
    def load_baseline(path: Path) -> dict:
        if not path.exists(): return {}
        try:
            b = json.loads(path.read_text())
            h = b.get("hash")
            if h and h != hash_state(b):
                return {"_tampered": True}
            return b
        except Exception:
            return {"_tampered": True}

    prev_baseline = load_baseline(prev_baseline_path)
    appr_baseline = load_baseline(appr_baseline_path)
    
    baseline_status = "OK"
    if prev_baseline.get("_tampered") or appr_baseline.get("_tampered"):
        baseline_status = "TAMPERED"
    elif not prev_baseline and not appr_baseline:
        baseline_status = "UNKNOWN"
        
    reference_baseline = appr_baseline if appr_baseline and not appr_baseline.get("_tampered") else prev_baseline
    if not reference_baseline or reference_baseline.get("_tampered"):
        reference_baseline = {}

    delta = {"changes": [], "risk_diff": 0, "schema_drifts": [], "authority": "UNKNOWN", "metrics": {}}
    
    # Delta vs reference
    if reference_baseline:
        ref_mcp = reference_baseline.get("mcp_count", 0)
        cur_mcp = current_state["mcp_count"]
        
        ref_cred = reference_baseline.get("cred_count", 0)
        cur_cred = current_state["cred_count"]
        
        ref_write = reference_baseline.get("external_write_count", 0)
        cur_write = current_state.get("external_write_count", 0)
        
        delta["metrics"] = {
            "BASELINE": ref_mcp + ref_cred,
            "CURRENT": cur_mcp + cur_cred,
            "CHANGE": (cur_mcp + cur_cred) - (ref_mcp + ref_cred)
        }
        
        if cur_mcp > ref_mcp: delta["changes"].append(f"+ Added MCP Server ({cur_mcp - ref_mcp} new)")
        elif cur_mcp < ref_mcp: delta["changes"].append(f"- Removed MCP Server ({ref_mcp - cur_mcp} removed)")
        
        if cur_cred > ref_cred: delta["changes"].append(f"+ Added Credential ({cur_cred - ref_cred} new)")
        elif cur_cred < ref_cred: delta["changes"].append(f"- Removed Credential ({ref_cred - cur_cred} removed)")
        
        if cur_write > ref_write: delta["changes"].append(f"~ Changed Authority (READ_ONLY -> EXTERNAL_WRITE)")
        elif cur_write < ref_write: delta["changes"].append(f"~ Changed Authority (EXTERNAL_WRITE -> READ_ONLY)")
        
        if cur_mcp > ref_mcp or cur_cred > ref_cred: delta["authority"] = "EXCEEDS_APPROVED"
        elif cur_write > ref_write: delta["authority"] = "CHANGED"
        elif cur_mcp < ref_mcp or cur_cred < ref_cred or cur_write < ref_write: delta["authority"] = "LESS_THAN_APPROVED"
        else: delta["authority"] = "UNCHANGED"
        
        for srv, fp in current_state["mcp_schemas"].items():
            old_fp = reference_baseline.get("mcp_schemas", {}).get(srv)
            if old_fp and old_fp != fp:
                delta["schema_drifts"].append(f"{srv}: {old_fp} -> {fp}")
                delta["changes"].append(f"~ {srv} schema changed")
                
    # Persist PREVIOUS baseline if requested
    if update_baseline and not demo_active():
        current_state["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        current_state["hash"] = hash_state(current_state)
        try: prev_baseline_path.write_text(json.dumps(current_state, sort_keys=True))
        except Exception: pass
        
    # 4. Safe To Run Policy
    safe = "SAFE"
    reasons = []
    
    if baseline_status == "TAMPERED":
        safe = "UNKNOWN"
        reasons.append("Baseline integrity validation failed (TAMPERED)")
        
    if delta["schema_drifts"]:
        safe = "BLOCKED"
        reasons.append("MCP tool schema changed since baseline - REVIEW REQUIRED")
        
    if delta["authority"] in ["EXCEEDS_APPROVED", "CHANGED"]:
        safe = "BLOCKED"
        reasons.append("Current authority explicitly escalated or exceeds approved baseline")
        
    if [f for f in all_findings if f.get("severity") == "S3"]:
        if safe == "SAFE": safe = "CONDITIONAL"
        reasons.append("S3 (Write Risk) findings detected")
        
    if blast_score > 70:
        if safe == "SAFE": safe = "CONDITIONAL"
        reasons.append("High blast radius detected")
        
    if not reasons and safe == "SAFE":
        reasons.append("All assertions passed")
        
    order = {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "UNKNOWN": -1}
    labels = {"S0": "CLEAN", "S1": "DRIFT", "S2": "SECRET RISK", "S3": "WRITE RISK", "UNKNOWN": "UNKNOWN"}
    known = [f.get("severity", "UNKNOWN") for f in all_findings if f.get("severity") in order and f.get("severity") != "UNKNOWN"]
    overall = max(known, key=lambda sev: order[sev]) if known else "UNKNOWN"

    # Export formatting
    delta["metrics"] = {
        "BASELINE": reference_baseline.get("mcp_count", 0) + reference_baseline.get("cred_count", 0) if reference_baseline else 0,
        "CURRENT": current_state["mcp_count"] + current_state["cred_count"]
    }
    delta["metrics"]["CHANGE"] = delta["metrics"]["CURRENT"] - delta["metrics"]["BASELINE"]

    return {
        "ok": True,
        "probe": "analyze",
        "overall": overall,
        "overall_label": labels[overall],
        "findings": [f.as_dict() if hasattr(f, "as_dict") else f for f in all_findings],
        "graph": graph,
        "delta": delta,
        "baseline_status": baseline_status,
        "blast_radius_score": blast_score,
        "risk_band": risk_band,
        "blast_contributors": blast_contributors,
        "blast_radius": {"score": min(blast_score, 100), "level": risk_band},
        "safe_to_run": {"decision": safe, "reasons": reasons},
        "write_baseline_semantics": {
            "external_writes": "NONE",
            "machine_mutation": "NONE",
            "local_state": "baseline metadata" if update_baseline else "NONE"
        }
    }

def analyze(args: argparse.Namespace) -> int:
    sys.stdout.write(json.dumps(analyze_payloads(load_payloads(args.payloads), str(getattr(args, "baseline", "false")).lower() == "true"), sort_keys=True) + "\n")
    return 0

# --- LAYER 4: OUTPUT ---

def render_human(payload: dict[str, Any]) -> str:
    lines = ["TRIPWIRE - AgentOps Control Layer", "===================================", ""]
    
    delta = payload.get("delta", {})
    def print_row(k, v, color=""): lines.append(f"{color}{k:<20} {v}\033[0m")
    print_row("BASELINE STATUS:", payload.get("baseline_status", "UNKNOWN"), "\033[93m" if payload.get("baseline_status") != "OK" else "\033[92m")
    print_row("BLAST RADIUS SCORE:", f"{payload.get('blast_radius_score', 0)}/100 ({payload.get('risk_band', 'UNKNOWN')})")
    
    metrics = delta.get("metrics", {"BASELINE": 0, "CURRENT": 0, "CHANGE": 0})
    lines.append("")
    lines.append("AGENT AUTHORITY DIFF")
    lines.append(f"  BASELINE       {metrics['BASELINE']}")
    lines.append(f"  CURRENT        {metrics['CURRENT']}")
    lines.append(f"  CHANGE         {'+' if metrics['CHANGE'] > 0 else ''}{metrics['CHANGE']}")
    if delta.get("changes"):
        lines.append("")
        for c in delta["changes"]: lines.append(f"  {c}")
    lines.append("")
        
    graph = payload.get("graph", [])
    if graph:
        lines.append("PERMISSION GRAPH")
        grouped = {}
        for g in graph:
            grouped.setdefault(g['agent'], {}).setdefault(g['tool_mcp'], []).append(g)
            
        for agent, servers in grouped.items():
            lines.append(f"  {agent}")
            for server, edges in servers.items():
                ev_type = edges[0].get('evidence_type', 'UNKNOWN').lower() if edges else 'unknown'
                conf = edges[0].get('confidence', 'UNKNOWN')
                lines.append(f"    └─[{ev_type}, {conf}]→ {server}")
                for idx, e in enumerate(edges):
                    prefix = "└─" if idx == len(edges) - 1 else "├─"
                    target = e.get('tool_name') or "capability metadata unavailable"
                    cap = e.get('effect', 'UNKNOWN')
                    t_conf = e.get('confidence', 'UNKNOWN')
                    lines.append(f"         {prefix}[{cap}, {t_conf}]→ {target}")
        lines.append("")
        
    lines.append("MCP INTEGRITY")
    lines.append(f"  Status: {payload.get('baseline_status', 'UNKNOWN')}")
    if delta.get("schema_drifts"):
        for drift in delta["schema_drifts"]:
            lines.append(f"  [!] {drift}")
    lines.append("")
        
    blast = payload.get("blast_radius", {})
    lines.append("BLAST RADIUS")
    lines.append(f"  Score: {blast.get('score', 0)}/100")
    lines.append(f"  RISK SCORE: {blast.get('level', 'UNKNOWN')}")
    lines.append("")
    
    safe = payload.get("safe_to_run", {})
    lines.append("SAFE TO RUN")
    lines.append(f"  POLICY DECISION: {safe.get('decision', 'UNKNOWN')}")
    for r in safe.get("reasons", []):
        lines.append(f"  Reason: {r}")
    lines.append("")
    
    wbs = payload.get("write_baseline_semantics", {})
    if wbs:
        lines.append("WRITE BASELINE SEMANTICS")
        lines.append(f"  External writes: {wbs.get('external_writes')}")
        lines.append(f"  Machine mutation: {wbs.get('machine_mutation')}")
        lines.append(f"  Local state: {wbs.get('local_state')}")
        lines.append("")
        
    lines.append("BLAST RADIUS CONTRIBUTORS")
    for c in payload.get("blast_contributors", []):
        lines.append(f"  {c}")
    if not payload.get("blast_contributors", []):
        lines.append("  None")
    lines.append("")
    
    lines.append("RAW FINDINGS")
    by_probe = {}
    for f in payload.get("findings", []):
        by_probe.setdefault(f.get("probe", "unknown"), []).append(f)
    for probe in sorted(by_probe):
        lines.append(probe)
        for finding in by_probe[probe]:
            sev = finding.get("severity", "UNKNOWN")
            name = finding.get("name", "unknown")
            msg = finding.get("message", "")
            lines.append(f"  {sev} {name}: {msg}")
            
    return "\n".join(lines)

def verdict(args: argparse.Namespace) -> int:
    payloads = load_payloads([args.analysis])
    payload = payloads[0] if payloads else analyze_payloads([])
    
    # Preserve Rote parity
    payload["write_contract"] = {
        "default_apply": False,
        "apply_requested": str(args.apply).lower() == "true",
        "revoke_stale": "DISABLED"
    }
    payload["provenance"] = {
        "tool": "tripwire",
        "version": "2.0.0",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workspace": safe_path(workspace())
    }
    
    if args.format == "summary":
        sys.stdout.write(f"TRIPWIRE {payload['overall']} {payload['overall_label']} findings={len(payload['findings'])}\n")
    elif args.format == "json":
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_human(payload) + "\n")
    return 0

def run_all(args: argparse.Namespace) -> int:
    configure_demo(str(getattr(args, "demo", "false")).lower() == "true")
    probe_funcs = [
        agent_identity, harness_inventory, mcp_census, play_registry, secret_loci,
        token_ttl, listen_surface, price_tape, git_leak_probe, filesystem_reachability, network_surface
    ]
    payloads = [run_probe_payload(func, args) for func in probe_funcs]
    analyzed = analyze_payloads(payloads, str(getattr(args, "baseline", "false")).lower() == "true")
    verdict_args = argparse.Namespace(scope=args.scope, apply=args.apply, format=args.format, analysis=json.dumps(analyzed))
    return verdict(verdict_args)

def doctor(args: argparse.Namespace) -> int:
    configure_demo(str(getattr(args, "demo", "false")).lower() == "true")
    result = {"ok": True, "probe": "doctor", "workspace": safe_path(workspace()), "safety": {"read_only_default": True}}
    if args.format == "human": sys.stdout.write("TRIPWIRE doctor\nread-only default: true\n")
    else: sys.stdout.write(json.dumps(result) + "\n")
    return 0

def investigate(args: argparse.Namespace) -> int:
    from bie import Investigator, BehaviorEvent
    
    configure_demo(str(getattr(args, "demo", "false")).lower() == "true")
    
    target_file = Path(args.target)
    if not target_file.exists():
        sys.stderr.write(f"Target trace file not found: {args.target}\n")
        return 1
        
    try:
        events_data = json.loads(target_file.read_text())
    except Exception as e:
        sys.stderr.write(f"Failed to parse target trace: {e}\n")
        return 1
        
    events = [BehaviorEvent(**e) for e in events_data]
    
    probe_funcs = [mcp_census]
    payloads = [run_probe_payload(func, args) for func in probe_funcs]
    analyzed = analyze_payloads(payloads, False)
    
    prev_baseline_path = workspace() / ".tripwire_previous.json"
    appr_baseline_path = workspace() / ".tripwire_approved.json"
    def load_baseline(path: Path) -> dict:
        if not path.exists(): return {}
        try: return json.loads(path.read_text())
        except Exception: return {}
        
    prev = load_baseline(prev_baseline_path)
    appr = load_baseline(appr_baseline_path)
    reference = appr if appr and not appr.get("_tampered") else prev
    
    agent_name = events[0].agent if events else "unknown-agent"
    
    investigator = Investigator(agent_name, reference, analyzed)
    result = investigator.run_investigation(events)
    
    if args.format == "json":
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        lines = ["TRIPWIRE Behavioral Investigation", "──────────────────────────────────", ""]
        lines.append(f"Target:\n  {result['target']}\n")
        lines.append(f"Finding:\n  {result['finding']}\n")
        lines.append(f"Risk:\n  {result['risk']}\n")
        lines.append(f"Confidence:\n  {result['confidence']}\n")
        
        lines.append("Hypotheses:\n")
        for h in result["hypotheses"]:
            lines.append(f"  {h['id']} {h['desc']:<35} {h['conf']}")
        lines.append("")
        
        lines.append("Selected Probe(s):")
        for p in result["probes"]:
            lines.append(f"  {p['type']} -> {p['target']}")
        lines.append("")
        
        lines.append("Evidence:")
        for e in result["evidence"]:
            lines.append(f"  {e['id']}: {e['obs']}")
        lines.append("")
        
        lines.append(f"Policy Decision:\n  {result['policy_decision']}\n")
        sys.stdout.write("\n".join(lines))
        
    return 0

def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description="TRIPWIRE AgentOps Control Layer")
    parser.add_argument("--scope", choices=["all", "harness", "mcp", "plays", "secrets", "filesystem", "network"], default="all")
    parser.add_argument("--apply", choices=["true", "false"], default="false")
    parser.add_argument("--format", choices=["human", "summary", "json"], default="human")
    parser.add_argument("--demo", choices=["true", "false"], default="false")
    parser.add_argument("--baseline", choices=["true", "false"], default="false", help="Update the PREVIOUS baseline")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ["agent_identity", "harness_inventory", "mcp_census", "play_registry", "secret_loci", "token_ttl", "listen_surface", "price_tape", "git_leak_probe", "filesystem_reachability", "network_surface", "doctor", "run_all"]:
        sub.add_parser(name)
    sub.add_parser("analyze").add_argument("payloads", nargs="*")
    sub.add_parser("investigate").add_argument("target")
    args = parser.parse_args(argv)
    
    if args.cmd == "analyze": return analyze(args)
    if args.cmd == "run_all": return run_all(args)
    if args.cmd == "doctor": return doctor(args)
    if args.cmd == "investigate": return investigate(args)
    
    # Run single probe
    funcs = {f.__name__: f for f in [agent_identity, harness_inventory, mcp_census, play_registry, secret_loci, token_ttl, listen_surface, price_tape, git_leak_probe, filesystem_reachability, network_surface]}
    return funcs[args.cmd](args)

if __name__ == "__main__":
    raise SystemExit(main())
