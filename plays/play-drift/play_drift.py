#!/usr/bin/env python3
"""PLAY-DRIFT inspector.

Checks for stale assumptions in installed Plays.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0

def stable_id(*parts):
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()[:16]

def check_dependencies(play_dir):
    deps_file = play_dir / "deps.toml"
    if not deps_file.exists():
        return []
    
    findings = []
    content = deps_file.read_text(errors="replace")
    
    # Very simple regex parsing for dependencies
    for match in re.finditer(r'command\s*=\s*"([^"]+)"', content):
        cmd = match.group(1)
        # Check if it's on PATH
        import shutil
        if not shutil.which(cmd):
            findings.append({
                "id": stable_id("drift", "dep", cmd),
                "severity": "WARNING",
                "status": "STALE",
                "title": f"Missing dependency: {cmd}",
                "evidence": f"The command {cmd} is required by deps.toml but not found on PATH.",
                "remediation": f"Install {cmd} or update deps.toml."
            })
    return findings

def check_stale_metadata(play_dir):
    main_ts = play_dir / "main.ts"
    if not main_ts.exists():
        return []
        
    findings = []
    content = main_ts.read_text(errors="replace")
    
    if "api.openai.com/v1/engines/" in content:
        findings.append({
            "id": stable_id("drift", "api", "openai_engines"),
            "severity": "WARNING",
            "status": "STALE",
            "title": "Stale OpenAI API endpoint",
            "evidence": "Found reference to deprecated /v1/engines/ endpoint.",
            "remediation": "Update to /v1/models/ or newer endpoints."
        })
        
    return findings

def inspect_drift(args):
    play_uri = args.play_uri
    path = Path(play_uri).expanduser()
    
    if not path.exists():
        return emit({
            "ok": False,
            "error": "Play path does not exist."
        })
        
    if path.is_file():
        play_dir = path.parent
    else:
        play_dir = path
        
    findings = []
    findings.extend(check_dependencies(play_dir))
    findings.extend(check_stale_metadata(play_dir))
    
    if not findings:
        findings.append({
            "id": stable_id("drift", "clean"),
            "severity": "S0",
            "status": "CLEAN",
            "title": "No drift detected",
            "evidence": "Dependencies and metadata appear up to date.",
            "remediation": "None"
        })
        
    result = {
        "name": "PLAY-DRIFT",
        "target": str(play_dir),
        "findings": findings,
        "overall": "CLEAN" if all(f.get("severity") == "S0" for f in findings) else "WARNING",
        "provenance": {"tool": "play-drift", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    }
    
    if args.format == "human":
        print(f"PLAY-DRIFT for {result['target']}")
        for f in findings:
            print(f"  {f['severity']} {f['status']}: {f['title']}")
        print(f"\nOverall: {result['overall']}")
    else:
        emit(result)
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="Identify stale assumptions in installed Plays.")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    parser.add_argument("cmd", choices=["inspect", "run_all"])
    parser.add_argument("play_uri", help="Path to the play directory or main.ts")
    args = parser.parse_args(argv)
    
    if args.cmd in ("inspect", "run_all"):
        return inspect_drift(args)
    return 0

if __name__ == "__main__":
    sys.exit(main())
