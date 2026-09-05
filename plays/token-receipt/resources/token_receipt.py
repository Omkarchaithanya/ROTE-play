#!/usr/bin/env python3
"""TOKEN-RECEIPT inspector.

Reconstruct local agent/harness usage and cost where data is available.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0

def inspect_receipt(args):
    home_dir = Path.home()
    if args.demo:
        home_dir = Path(args.demo)

    findings = []
    
    # Check Cursor usage (mock logic)
    cursor_log = home_dir / ".cursor" / "logs" / "usage.json"
    if cursor_log.exists():
        try:
            data = json.loads(cursor_log.read_text())
            tokens = data.get("total_tokens", 0)
            cost = data.get("estimated_cost", "UNKNOWN")
            findings.append({
                "source": "Cursor",
                "date_range": data.get("date_range", "UNKNOWN"),
                "model": data.get("model", "UNKNOWN"),
                "usage": f"{tokens} tokens",
                "estimated_cost": f"${cost}" if cost != "UNKNOWN" else "UNKNOWN",
                "status": "KNOWN"
            })
        except Exception:
            findings.append({
                "source": "Cursor",
                "status": "UNKNOWN",
                "message": "Unreadable usage.json"
            })
    
    # Check general Claude usage
    claude_log = home_dir / ".claude" / "telemetry.json"
    if claude_log.exists():
        findings.append({
            "source": "Claude",
            "date_range": "UNKNOWN",
            "model": "UNKNOWN",
            "usage": "Data present but encrypted/unsupported",
            "estimated_cost": "UNKNOWN",
            "status": "NOT AVAILABLE"
        })
        
    if not findings:
        findings.append({
            "source": "all",
            "status": "NOT AVAILABLE",
            "message": "No local usage logs found"
        })

    result = {
        "name": "TOKEN-RECEIPT",
        "findings": findings,
        "provenance": {"tool": "token-receipt", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    }
    
    if args.format == "human":
        print("TOKEN-RECEIPT")
        for f in findings:
            print(f"\nSource: {f['source']} ({f['status']})")
            if f['status'] == 'KNOWN':
                print(f"  Date Range: {f.get('date_range')}")
                print(f"  Model: {f.get('model')}")
                print(f"  Usage: {f.get('usage')}")
                print(f"  Cost: {f.get('estimated_cost')}")
            else:
                print(f"  Message: {f.get('message', f.get('usage', 'N/A'))}")
    else:
        emit(result)
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="Reconstruct local agent spend.")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    parser.add_argument("--demo", help="Use an alternate home directory for testing.")
    args = parser.parse_args(argv)
    return inspect_receipt(args)

if __name__ == "__main__":
    sys.exit(main())
