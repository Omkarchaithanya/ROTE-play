#!/usr/bin/env python3
"""PREFLIGHT Superplay.

Integrates TRIPWIRE, PLAY-DRIFT, and WRITE-GUARD-XRAY.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0

def run_subplay(cmd: list[str]) -> dict:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        try:
            return json.loads(e.stdout)
        except Exception:
            return {"ok": False, "error": "Subplay failed", "stderr": e.stderr}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def run_preflight(args):
    repo_root = Path(__file__).resolve().parent.parent.parent
    python = sys.executable

    # Run TRIPWIRE
    tripwire_script = repo_root / "scripts" / "tripwire.py"
    cmd_tripwire = [python, str(tripwire_script), "--format", "json", "run_all"]
    if args.demo:
        cmd_tripwire.extend(["--demo", "true"])
    res_tripwire = run_subplay(cmd_tripwire)

    # Run PLAY-DRIFT (on current repo)
    drift_script = repo_root / "plays" / "play-drift" / "play_drift.py"
    cmd_drift = [python, str(drift_script), "--format", "json", "inspect", str(repo_root)]
    res_drift = run_subplay(cmd_drift)

    # Run WRITE-GUARD-XRAY (on TRIPWIRE itself as a test, or a provided play)
    xray_target = args.xray_target if args.xray_target else str(repo_root / "main.ts")
    xray_script = repo_root / "plays" / "write-guard-xray" / "write_guard_xray.py"
    cmd_xray = [python, str(xray_script), "--format", "json", "run_all", xray_target]
    res_xray = run_subplay(cmd_xray)

    # Determine overall verdict
    # severity ranking: S3 > S2 > S1 > S0 > UNKNOWN
    order = {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "UNKNOWN": -1}
    severities = []
    
    if res_tripwire.get("overall"):
        severities.append(res_tripwire["overall"].split()[0]) # e.g. "S3" from "S3 WRITE RISK"
    if res_drift.get("overall") == "WARNING":
        severities.append("S1")
    elif res_drift.get("overall") == "CLEAN":
        severities.append("S0")
    if res_xray.get("overall"):
        severities.append(res_xray.get("overall"))

    severities = [s for s in severities if s in order]
    overall = max(severities, key=lambda s: order[s]) if severities else "UNKNOWN"

    result = {
        "name": "PREFLIGHT",
        "overall": overall,
        "results": {
            "TRIPWIRE": res_tripwire,
            "PLAY-DRIFT": res_drift,
            "WRITE-GUARD-XRAY": res_xray
        },
        "provenance": {"tool": "preflight", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    }

    if args.format == "human":
        print("=============================")
        print("PREFLIGHT SUPERPLAY")
        print("=============================\n")
        
        print(f"TRIPWIRE Verdict: {res_tripwire.get('overall', 'ERROR')}")
        print(f"PLAY-DRIFT Verdict: {res_drift.get('overall', 'ERROR')}")
        print(f"WRITE-GUARD-XRAY Verdict: {res_xray.get('overall', 'ERROR')}")
        
        print("\n-----------------------------")
        print(f"OVERALL PREFLIGHT VERDICT: {overall}")
        print("-----------------------------")
    else:
        emit(result)
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="Run AgentOps preflight checks.")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    parser.add_argument("--demo", action="store_true", help="Run TRIPWIRE in demo mode")
    parser.add_argument("--xray-target", help="Play to inspect with WRITE-GUARD-XRAY (defaults to TRIPWIRE)")
    args = parser.parse_args(argv)
    return run_preflight(args)

if __name__ == "__main__":
    sys.exit(main())
