#!/usr/bin/env python3
"""WRITE-GUARD-XRAY inspector.

Read-only Rote Play inspector. It does not execute the target Play.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|password|passwd|credential|credentials|cookie|bearer|oauth|(^|[_\-.])token($|[_\-.])|(^|[_\-.])secret($|[_\-.]))",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
WRITE_ACTION_RE = re.compile(
    r"\b(rm|remove-item|del|delete|unlink|rmdir|move-item|mv|write|writefile|set-content|add-content|out-file|copy-item|cp|put|post|patch|create|update|upsert|revoke|rotate|disable|enable|deploy|publish|push|commit|merge|apply|terraform\s+apply|kubectl\s+apply|wrangler\s+deploy|eval|wget\s+.*\|\s*(bash|sh)|curl\s+.*\|\s*(bash|sh)|base64\s+-d\s*\|\s*(bash|sh))\b",
    re.IGNORECASE,
)
GUARD_RE = re.compile(r"\b(apply\s*==?\s*true|apply=true|dry[-_ ]run|read[-_ ]only|confirm|--dry-run|--check)\b", re.IGNORECASE)
READONLY_RE = re.compile(r"\b(read[-_ ]only|writes?\s*:\s*(none|no|false)|no writes?|read_only_default\s*:\s*true)\b", re.IGNORECASE)


@dataclass
class Finding:
    id: str
    severity: str
    status: str
    title: str
    evidence: str
    declared: str = "UNKNOWN"
    observed: str = "UNKNOWN"
    guarded: str = "UNKNOWN"
    confidence: str = "medium"
    remediation: str = "Review the Play metadata and step definitions."
    details: dict[str, Any] = field(default_factory=dict)


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_NAME_RE.search(str(key)):
                out[str(key)] = "PRESENT"
            else:
                out[str(key)] = scrub(item)
        return out
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        return "NEVER DISPLAYED" if SECRET_VALUE_RE.search(value) else value
    return value


def stable_id(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode("utf-8", errors="replace")).hexdigest()[:16]


def emit(payload: dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(scrub(payload), sort_keys=True) + "\n")
    return 0


def read_target(play_uri: str) -> dict[str, Any]:
    parsed = urlparse(play_uri)
    if parsed.scheme in {"http", "https"}:
        try:
            req = Request(play_uri, headers={"User-Agent": "write-guard-xray/0.1"})
            with urlopen(req, timeout=12) as response:
                body = response.read(2_000_000).decode("utf-8", errors="replace")
            return {"ok": True, "source_kind": "url", "source": play_uri, "text": body}
        except (OSError, URLError, TimeoutError) as exc:
            return {
                "ok": False,
                "source_kind": "url",
                "source": play_uri,
                "status": "UNKNOWN",
                "error": exc.__class__.__name__,
                "message": "URI unavailable or not directly fetchable without Rote registry tooling.",
            }
    path = Path(play_uri).expanduser()
    if path.is_dir():
        path = path / "main.ts"
    try:
        if not path.exists():
            return {"ok": False, "source_kind": "path", "source": play_uri, "status": "UNKNOWN", "message": "Play path does not exist."}
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"ok": True, "source_kind": "path", "source": str(path.resolve()), "text": text}
    except OSError as exc:
        return {"ok": False, "source_kind": "path", "source": play_uri, "status": "UNKNOWN", "error": exc.__class__.__name__, "message": "Play path unreadable."}


def extract_frontmatter(text: str) -> dict[str, Any]:
    match = re.search(r"/\*\*\s*@rote-frontmatter\s*(.*?)\*/", text, re.DOTALL)
    if not match:
        return {"ok": False, "raw": "", "message": "No @rote-frontmatter block found."}
    raw = match.group(1)
    return {"ok": True, "raw": raw}


def simple_yaml_value(value: str) -> Any:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [part.strip().strip("'\"") for part in inner.split(",")]
    lowered = value.lower().strip("'\"")
    if lowered in {"true", "false"}:
        return lowered == "true"
    return value.strip("'\"")


def parse_top_level(raw: str) -> dict[str, Any]:
    meta: dict[str, Any] = {"parameters": [], "steps": {}}
    current_step: str | None = None
    in_parameters = False
    current_param: dict[str, Any] | None = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][\w-]*:", line):
            current_step = None
            in_parameters = False
            key, value = line.split(":", 1)
            key = key.strip()
            if key == "parameters":
                in_parameters = True
                continue
            if key == "steps":
                continue
            meta[key] = simple_yaml_value(value)
            continue
        if line.startswith("- ") and "name:" in line and "parameters" in raw:
            current_param = {}
            in_parameters = True
            _, value = line.split("name:", 1)
            current_param["name"] = simple_yaml_value(value)
            meta["parameters"].append(current_param)
            continue
        if in_parameters and current_param is not None and line.startswith("  ") and ":" in line:
            key, value = line.split(":", 1)
            current_param[key.strip()] = simple_yaml_value(value)
            continue
        step_match = re.match(r"^\s{2}([A-Za-z_][\w-]*):\s*$", line)
        if step_match:
            current_step = step_match.group(1)
            meta["steps"][current_step] = {"raw": []}
            continue
        if current_step and line.startswith("    "):
            meta["steps"][current_step]["raw"].append(line.strip())
            if ":" in line.strip():
                key, value = line.strip().split(":", 1)
                meta["steps"][current_step][key.strip()] = simple_yaml_value(value)
    return meta


def metadata_probe(args: argparse.Namespace) -> int:
    target = read_target(args.play_uri)
    if not target.get("ok"):
        return emit(
            {
                "ok": True,
                "probe": "metadata_probe",
                "warnings": [target.get("message", "target unavailable")],
                "metadata": {"status": "UNKNOWN", "source": target.get("source"), "source_kind": target.get("source_kind")},
                "findings": [
                    Finding(
                        stable_id("metadata", args.play_uri),
                        "UNKNOWN",
                        "UNKNOWN",
                        "Play metadata unavailable",
                        target.get("message", "target unavailable"),
                        remediation="Inspect with Rote CLI or provide a local main.ts path.",
                    ).__dict__
                ],
            }
        )
    frontmatter = extract_frontmatter(target["text"])
    meta = parse_top_level(frontmatter["raw"]) if frontmatter.get("ok") else {}
    return emit(
        {
            "ok": True,
            "probe": "metadata_probe",
            "warnings": [] if frontmatter.get("ok") else [frontmatter.get("message", "frontmatter unavailable")],
            "metadata": {
                "status": "VERIFIED" if frontmatter.get("ok") else "UNKNOWN",
                "source": target["source"],
                "source_kind": target["source_kind"],
                "name": meta.get("name", "UNKNOWN"),
                "version": meta.get("version", "UNKNOWN"),
                "description": meta.get("description", "UNKNOWN"),
                "parameter_count": len(meta.get("parameters", [])),
                "step_count": len(meta.get("steps", {})),
            },
            "frontmatter": frontmatter.get("raw", ""),
            "text": target["text"],
            "parsed": meta,
            "findings": [],
        }
    )


def capability_probe(args: argparse.Namespace) -> int:
    upstream = json.loads(args.metadata_json)
    raw = upstream.get("frontmatter", "")
    parsed = upstream.get("parsed", {})
    readonly_declared = bool(READONLY_RE.search(raw))
    apply_param = any(param.get("name") == "apply" for param in parsed.get("parameters", []))
    declared = "READ_ONLY" if readonly_declared else ("WRITES_DECLARED" if "write" in raw.lower() or apply_param else "UNKNOWN")
    guard = "VERIFIED" if apply_param or GUARD_RE.search(raw) else "UNKNOWN"
    findings = []
    if declared == "UNKNOWN":
        findings.append(
            Finding(
                stable_id("capability", "unknown", upstream.get("metadata", {}).get("source", "")),
                "S1",
                "UNKNOWN",
                "Declared write capability is ambiguous",
                "No clear read-only or write declaration found.",
                declared="UNKNOWN",
                guarded=guard,
                remediation="Add explicit writes/read-only metadata and an apply=false guard for any mutation.",
            ).__dict__
        )
    return emit(
        {
            "ok": True,
            "probe": "capability_probe",
            "warnings": upstream.get("warnings", []),
            "declared": {"write_capability": declared, "guard": guard, "apply_parameter": apply_param, "readonly_declared": readonly_declared},
            "metadata": upstream.get("metadata", {}),
            "frontmatter": raw,
            "text": upstream.get("text", ""),
            "parsed": parsed,
            "findings": findings,
        }
    )


def step_tool_probe(args: argparse.Namespace) -> int:
    upstream = json.loads(args.capability_json)
    parsed = upstream.get("parsed", {})
    steps = parsed.get("steps", {})
    observed_steps = []
    findings = []
    for name, cfg in steps.items():
        raw = "\n".join(cfg.get("raw", []))
        write_match = WRITE_ACTION_RE.search(raw)
        guard_match = GUARD_RE.search(raw)
        observed = "WRITE_CAPABLE" if write_match else "NO_WRITE_EVIDENCE"
        guarded = "VERIFIED" if guard_match else ("NOT_APPLICABLE" if not write_match else "MISSING")
        observed_steps.append({"step": name, "observed": observed, "guarded": guarded, "evidence": write_match.group(0) if write_match else "none"})
        if write_match:
            findings.append(
                Finding(
                    stable_id("step", name, write_match.group(0)),
                    "S1",
                    "VERIFIED",
                    "Write-capable operation represented in step",
                    f"Step {name} contains write-like token: {write_match.group(0)}",
                    observed="WRITE_CAPABLE",
                    guarded=guarded,
                    remediation="Confirm this write is declared and gated by apply=false or equivalent.",
                ).__dict__
            )
    return emit(
        {
            "ok": True,
            "probe": "step_tool_probe",
            "warnings": upstream.get("warnings", []),
            "declared": upstream.get("declared", {}),
            "metadata": upstream.get("metadata", {}),
            "steps": observed_steps,
            "findings": upstream.get("findings", []) + findings,
        }
    )


def write_analysis(args: argparse.Namespace) -> int:
    upstream = json.loads(args.steps_json)
    declared = upstream.get("declared", {})
    steps = upstream.get("steps", [])
    write_steps = [step for step in steps if step.get("observed") == "WRITE_CAPABLE"]
    unguarded = [step for step in write_steps if step.get("guarded") == "MISSING"]
    readonly = declared.get("write_capability") == "READ_ONLY"
    findings = list(upstream.get("findings", []))
    if readonly and write_steps:
        findings.append(
            Finding(
                stable_id("analysis", "readonly-mismatch", upstream.get("metadata", {}).get("source", "")),
                "S3",
                "MISMATCH",
                "Declared read-only behavior conflicts with represented write capability",
                f"{len(write_steps)} write-capable step(s) found while metadata declares read-only behavior.",
                declared="READ_ONLY",
                observed="WRITE_CAPABLE",
                guarded="VERIFIED" if not unguarded else "MISSING",
                confidence="high",
                remediation="Either remove the write-capable step, declare the write, or gate it behind apply=false with clear metadata.",
            ).__dict__
        )
    elif unguarded:
        findings.append(
            Finding(
                stable_id("analysis", "unguarded", upstream.get("metadata", {}).get("source", "")),
                "S3",
                "MISMATCH",
                "Write-capable step lacks an obvious guard",
                f"{len(unguarded)} write-capable step(s) have no apply/dry-run/read-only guard evidence.",
                declared=declared.get("write_capability", "UNKNOWN"),
                observed="WRITE_CAPABLE",
                guarded="MISSING",
                confidence="high",
                remediation="Add an explicit apply=false parameter and make the write path no-op unless apply=true.",
            ).__dict__
        )
    elif write_steps:
        findings.append(
            Finding(
                stable_id("analysis", "guarded-write", upstream.get("metadata", {}).get("source", "")),
                "S0",
                "VERIFIED",
                "Write-capable steps appear guarded or declared",
                f"{len(write_steps)} write-capable step(s) found with guard/declaration evidence.",
                declared=declared.get("write_capability", "UNKNOWN"),
                observed="WRITE_CAPABLE",
                guarded="VERIFIED",
                confidence="medium",
                remediation="Keep the write contract visible in the Play card.",
            ).__dict__
        )
    else:
        findings.append(
            Finding(
                stable_id("analysis", "no-write", upstream.get("metadata", {}).get("source", "")),
                "S0",
                "VERIFIED",
                "No represented write capability detected",
                "No write-like step commands or actions found.",
                declared=declared.get("write_capability", "UNKNOWN"),
                observed="NO_WRITE_EVIDENCE",
                guarded="NOT_APPLICABLE",
                confidence="medium",
                remediation="No action required.",
            ).__dict__
        )
    return emit(
        {
            "ok": True,
            "probe": "write_analysis",
            "warnings": upstream.get("warnings", []),
            "metadata": upstream.get("metadata", {}),
            "declared": declared,
            "steps": steps,
            "findings": findings,
        }
    )


def classify(findings: list[dict[str, Any]]) -> tuple[str, str, dict[str, int]]:
    order = {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "UNKNOWN": -1}
    labels = {"S0": "NO WRITE MISMATCH", "S1": "AMBIGUITY OR DRIFT", "S2": "SENSITIVE CONFIGURATION CONCERN", "S3": "WRITE RISK", "UNKNOWN": "UNKNOWN"}
    counts = {"S0": 0, "S1": 0, "S2": 0, "S3": 0, "UNKNOWN": 0}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        counts[severity if severity in counts else "UNKNOWN"] += 1
    known = [finding.get("severity", "UNKNOWN") for finding in findings if finding.get("severity") in order and finding.get("severity") != "UNKNOWN"]
    overall = max(known, key=lambda sev: order[sev]) if known else "UNKNOWN"
    return overall, labels[overall], counts


def render_human(result: dict[str, Any]) -> str:
    lines = [
        "WRITE-GUARD-XRAY",
        "",
        "Play:",
        f"  {result['metadata'].get('name', 'UNKNOWN')}",
        "",
        "Version:",
        f"  {result['metadata'].get('version', 'UNKNOWN')}",
        "",
        "Declared:",
        f"  writes: {result['declared'].get('write_capability', 'UNKNOWN')}",
        f"  guard: {result['declared'].get('guard', 'UNKNOWN')}",
        "",
        "Observed/Represented:",
        f"  write-capable steps: {sum(1 for step in result.get('steps', []) if step.get('observed') == 'WRITE_CAPABLE')}",
        f"  unguarded write-capable steps: {sum(1 for step in result.get('steps', []) if step.get('guarded') == 'MISSING')}",
        "",
        "Findings:",
    ]
    for finding in result.get("findings", []):
        lines.append(f"  {finding.get('severity', 'UNKNOWN')} {finding.get('status', 'UNKNOWN')}: {finding.get('title', 'finding')}")
    if result.get("warnings"):
        lines.extend(["", "Warnings:"])
        lines.extend(f"  WARNING {warning}" for warning in result["warnings"])
    lines.extend(["", "Classification:", f"  {result['overall']} - {result['overall_label']}", "", "Verdict:", f"  {result['verdict']}"])
    return "\n".join(lines)


def verdict(args: argparse.Namespace) -> int:
    upstream = json.loads(args.analysis_json)
    findings = upstream.get("findings", [])
    overall, label, counts = classify(findings)
    verdict_text = {
        "S0": "DECLARATION MATCHES REPRESENTED CAPABILITY",
        "S1": "DECLARATION OR METADATA NEEDS REVIEW",
        "S2": "SENSITIVE CONFIGURATION NEEDS REVIEW",
        "S3": "DECLARATION DOES NOT MATCH CAPABILITY",
        "UNKNOWN": "INSPECTION INCOMPLETE",
    }[overall]
    result = {
        "ok": True,
        "name": "WRITE-GUARD-XRAY",
        "version": "0.1.0",
        "target": args.play_uri,
        "metadata": upstream.get("metadata", {}),
        "declared": upstream.get("declared", {}),
        "steps": upstream.get("steps", []),
        "findings": findings,
        "counts": counts,
        "overall": overall,
        "overall_label": label,
        "verdict": verdict_text,
        "warnings": upstream.get("warnings", []),
        "safety": {"read_only": True, "executes_target_play": False, "modifies_target_play": False, "secrets": "values never displayed"},
        "provenance": {"tool": "write-guard-xray", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    }
    if args.format == "human":
        sys.stdout.write(render_human(result) + "\n")
    else:
        sys.stdout.write(json.dumps(scrub(result), sort_keys=True) + "\n")
    return 0


def run_all(args: argparse.Namespace) -> int:
    meta_stream = capture(metadata_probe, args)
    cap_args = argparse.Namespace(metadata_json=meta_stream)
    cap_stream = capture(capability_probe, cap_args)
    step_args = argparse.Namespace(capability_json=cap_stream)
    step_stream = capture(step_tool_probe, step_args)
    analysis_args = argparse.Namespace(steps_json=step_stream)
    analysis_stream = capture(write_analysis, analysis_args)
    verdict_args = argparse.Namespace(play_uri=args.play_uri, analysis_json=analysis_stream, format=args.format)
    return verdict(verdict_args)


def capture(func: Any, args: argparse.Namespace) -> str:
    old_stdout = sys.stdout
    from io import StringIO

    stream = StringIO()
    sys.stdout = stream
    try:
        func(args)
    finally:
        sys.stdout = old_stdout
    return stream.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a Rote Play for declared-vs-represented write capability.")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    parser.add_argument("cmd", choices=["metadata_probe", "capability_probe", "step_tool_probe", "write_analysis", "verdict", "run_all"])
    parser.add_argument("play_uri", nargs="?")
    parser.add_argument("--metadata-json", default="")
    parser.add_argument("--capability-json", default="")
    parser.add_argument("--steps-json", default="")
    parser.add_argument("--analysis-json", default="")
    args = parser.parse_args(argv)
    if args.cmd in {"metadata_probe", "run_all"} and not args.play_uri:
        return emit({"ok": False, "error": "play_uri is required"})
    handlers = {
        "metadata_probe": metadata_probe,
        "capability_probe": capability_probe,
        "step_tool_probe": step_tool_probe,
        "write_analysis": write_analysis,
        "verdict": verdict,
        "run_all": run_all,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
