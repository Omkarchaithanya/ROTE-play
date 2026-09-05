#!/usr/bin/env python3
"""TRIBAL-FIVE inspector.

Recover important repository knowledge that normally lives in engineers' heads.
"""

import argparse
import json
import sys
import time
from pathlib import Path

def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0

def inspect_tribal_knowledge(args):
    # Questions specific to this repository
    findings = [
        {
            "question": "Is this a general-purpose security scanner?",
            "answer": "No. It is a local-first read-only probe engine for AgentOps census.",
            "type": "FACT",
            "source": "README.md",
            "warnings": ["Do not confuse it with SaaS vulnerability scanners."]
        },
        {
            "question": "Does it upload credentials?",
            "answer": "It NEVER sends credentials externally.",
            "type": "FACT",
            "source": "README.md 'Security Guarantees'",
            "warnings": ["It reports presence (PRESENT), never the value."]
        },
        {
            "question": "What happens if a tool like 'gh' is missing?",
            "answer": "It gracefully degrades to UNKNOWN.",
            "type": "FACT",
            "source": "deps.toml",
            "warnings": []
        },
        {
            "question": "How are findings classified?",
            "answer": "From S0 (CLEAN) to S3 (WRITE RISK).",
            "type": "FACT",
            "source": "README.md 'Classification'",
            "warnings": ["UNKNOWN is never escalated to S2 or S3."]
        },
        {
            "question": "Can it automatically revoke stale credentials?",
            "answer": "The capability is disabled by default for safety.",
            "type": "INFERENCE",
            "source": "README.md 'Read/Write Behavior'",
            "warnings": ["Do not enable revoke_stale without a safe local adapter."]
        }
    ]

    result = {
        "name": "TRIBAL-FIVE",
        "findings": findings,
        "provenance": {"tool": "tribal-five", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    }
    
    if args.format == "human":
        print("TRIBAL-FIVE")
        for i, f in enumerate(findings, 1):
            print(f"\nQ{i}: {f['question']}")
            print(f"[{f['type']}] {f['answer']}")
            print(f"Source: {f['source']}")
            for w in f['warnings']:
                print(f"WARNING: {w}")
    else:
        emit(result)
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="Answer the five tribal knowledge questions.")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    args = parser.parse_args(argv)
    return inspect_tribal_knowledge(args)

if __name__ == "__main__":
    sys.exit(main())
