#!/usr/bin/env python3
"""Disabled revocation step for the TRIPWIRE census play."""

from __future__ import annotations

import json
import sys


def main() -> int:
    apply_requested = len(sys.argv) > 1 and str(sys.argv[1]).lower() == "true"
    print(json.dumps({
        "ok": True,
        "probe": "revoke_stale",
        "status": "disabled",
        "apply_requested": apply_requested,
        "message": "revoke_stale is intentionally disabled until a safe local revocation adapter is available",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
