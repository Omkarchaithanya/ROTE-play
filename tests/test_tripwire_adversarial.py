import contextlib
import io
import json
import tempfile
import unittest
import os
import sys
from pathlib import Path
from unittest import mock

import scripts.tripwire as tripwire

def ns(**kwargs):
    defaults = {"scope": "all", "apply": "false", "format": "json", "demo": "false"}
    defaults.update(kwargs)
    return type("Args", (), defaults)()

def capture_json(func, *args):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        func(*args)
    return json.loads(stream.getvalue())

class TripwireAdversarialTests(unittest.TestCase):
    
    def test_tool_classification_false_positive(self):
        # 1. read_deployment_status should be READ_ONLY, not EXTERNAL_WRITE
        tool = {"name": "read_deployment_status", "description": "Fetches the status of a deployment"}
        cap = tripwire.infer_tool_capability("cloudflare", tool)
        self.assertEqual(cap, tripwire.ACTION_READ_ONLY)
        
        # Ambiguous tool: deploy_readiness_check (has both deploy and check)
        tool2 = {"name": "deploy_readiness_check", "description": "Checks if ready to deploy"}
        cap2 = tripwire.infer_tool_capability("cloudflare", tool2)
        self.assertEqual(cap2, tripwire.ACTION_UNKNOWN)

    def test_semantic_delta_12_to_12(self):
        # 4 & 7. 12 -> 12 where READ_ONLY becomes EXTERNAL_WRITE
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 12, "cred_count": 0, "mcp_schemas": {}, "external_write_count": 0})
            (ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 12, "cred_count": 0, "mcp_schemas": {}, "external_write_count": 0, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(ws)}):
                # Current: 12 MCPs, but one has EXTERNAL_WRITE
                payloads = [{"findings": [{"probe": "mcp_census", "status": "ok", "details": {"server_names": ["s1"], "write_capabilities": [{"server": "s1", "tool": "t1", "write_capability": tripwire.ACTION_EXTERNAL_WRITE}]}}]}]
                payloads.extend([{"findings": [{"probe": "mcp_census", "status": "ok"}]} for _ in range(11)])
                res = tripwire.analyze_payloads(payloads)
                # Should detect CHANGED authority
                self.assertIn("CHANGED", res["delta"]["authority"])
                self.assertEqual(res["safe_to_run"]["decision"], "BLOCKED")

    def test_authority_removal_with_schema_drift(self):
        # 6. Authority removal does not get treated as dangerous escalation merely because MCP integrity drift occurred.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 12, "cred_count": 0, "mcp_schemas": {"s1": "hashA"}})
            (ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 12, "cred_count": 0, "mcp_schemas": {"s1": "hashA"}, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(ws)}):
                # We return only 11 MCPs, but one changed hash
                payloads = [{"findings": [{"probe": "mcp_census", "status": "ok", "details": {"tools_fingerprint": {"s1": {"fingerprint": "hashB"}}}}]}]
                payloads.extend([{"findings": [{"probe": "mcp_census", "status": "ok"}]} for _ in range(10)])
                res = tripwire.analyze_payloads(payloads)
                self.assertEqual(res["delta"]["metrics"]["CHANGE"], -1)
                self.assertNotEqual(res["delta"]["authority"], "EXCEEDS_APPROVED")

    def test_credential_exposure_distinctions(self):
        # 3. distinguishing usability
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("TOKEN=never-print")
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root / "home"), "TRIPWIRE_WORKSPACE": str(root)}):
                payload = capture_json(tripwire.secret_loci, ns())
            f = payload["findings"][0]
            self.assertEqual(f["severity"], "S2")
            self.assertEqual(f["details"]["presence"], "PRESENT")
            self.assertEqual(f["details"].get("agent_usable"), "UNKNOWN")

    def test_zero_leak_immutability(self):
        # 8 & 9. Prove secret values never appear and no mutations occur
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            (root / ".env").write_text("SUPERSECRET12345")
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(home), "TRIPWIRE_WORKSPACE": str(root)}):
                with mock.patch.object(os, "chmod") as mock_chmod, mock.patch.object(Path, "write_text") as mock_write:
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                        tripwire.main(["--format", "json", "run_all"])
                    output = stream.getvalue()
                    self.assertNotIn("SUPERSECRET12345", output)
                    mock_chmod.assert_not_called()
                    mock_write.assert_not_called()

if __name__ == "__main__":
    unittest.main()
