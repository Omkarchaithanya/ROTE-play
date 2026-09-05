import json
import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to the path so we can import write_guard_xray
sys.path.insert(0, str(Path(__file__).parent.parent))

import write_guard_xray

FIXTURE_DIR = Path(__file__).parent / "fixtures"

class TestWriteGuardXray(unittest.TestCase):
    def run_all_for(self, filename: str) -> dict:
        uri = str(FIXTURE_DIR / filename)
        
        class Args:
            play_uri = uri
            format = "json"
            
        meta_stream = write_guard_xray.capture(write_guard_xray.metadata_probe, Args())
        
        class CapArgs:
            metadata_json = meta_stream
        cap_stream = write_guard_xray.capture(write_guard_xray.capability_probe, CapArgs())
        
        class StepArgs:
            capability_json = cap_stream
        step_stream = write_guard_xray.capture(write_guard_xray.step_tool_probe, StepArgs())
        
        class AnalysisArgs:
            steps_json = step_stream
        analysis_stream = write_guard_xray.capture(write_guard_xray.write_analysis, AnalysisArgs())
        
        class VerdictArgs:
            play_uri = uri
            analysis_json = analysis_stream
            format = "json"
        
        result_str = write_guard_xray.capture(write_guard_xray.verdict, VerdictArgs())
        return json.loads(result_str)

    def test_readonly_play(self):
        result = self.run_all_for("readonly.ts")
        self.assertEqual(result["overall"], "S0")
        self.assertEqual(result["verdict"], "DECLARATION MATCHES REPRESENTED CAPABILITY")
        self.assertEqual(result["declared"]["write_capability"], "READ_ONLY")

    def test_unguarded_write_play(self):
        result = self.run_all_for("write_unguarded.ts")
        self.assertEqual(result["overall"], "S3")
        self.assertEqual(result["verdict"], "DECLARATION DOES NOT MATCH CAPABILITY")
        
        # Check that we found unguarded writes
        unguarded_findings = [f for f in result["findings"] if f["id"] == write_guard_xray.stable_id("analysis", "unguarded", str(FIXTURE_DIR / "write_unguarded.ts"))]
        self.assertTrue(len(unguarded_findings) > 0)

    def test_guarded_write_play(self):
        result = self.run_all_for("write_guarded.ts")
        self.assertEqual(result["overall"], "S1")
        self.assertEqual(result["declared"]["guard"], "VERIFIED")

    def test_mismatch_play(self):
        result = self.run_all_for("mismatch.ts")
        self.assertEqual(result["overall"], "S3")
        self.assertEqual(result["verdict"], "DECLARATION DOES NOT MATCH CAPABILITY")
        
        # Check for readonly-mismatch
        mismatch_findings = [f for f in result["findings"] if f["id"] == write_guard_xray.stable_id("analysis", "readonly-mismatch", str(FIXTURE_DIR / "mismatch.ts"))]
        self.assertTrue(len(mismatch_findings) > 0)

    def test_obfuscated_payload(self):
        result = self.run_all_for("obfuscated.ts")
        self.assertEqual(result["overall"], "S3")
        # Should catch the curl ... | bash pattern as a write capability
        unguarded_findings = [f for f in result["findings"] if f["id"] == write_guard_xray.stable_id("analysis", "unguarded", str(FIXTURE_DIR / "obfuscated.ts"))]
        self.assertTrue(len(unguarded_findings) > 0)

    def test_scrub_secrets(self):
        # Ensure scrub actually removes secrets
        secret_payload = {
            "api_key": "sk-12345678901234567890",
            "safe_value": "hello"
        }
        scrubbed = write_guard_xray.scrub(secret_payload)
        self.assertEqual(scrubbed["api_key"], "PRESENT")
        self.assertEqual(scrubbed["safe_value"], "hello")

if __name__ == "__main__":
    unittest.main()
