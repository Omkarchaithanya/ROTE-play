import json
import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to the path so we can import play_drift
sys.path.insert(0, str(Path(__file__).parent.parent))

import play_drift

FIXTURE_DIR = Path(__file__).parent / "fixtures"

class TestPlayDrift(unittest.TestCase):
    def setUp(self):
        # Create dummy fixtures
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        
        self.clean_dir = FIXTURE_DIR / "clean_play"
        self.clean_dir.mkdir(exist_ok=True)
        (self.clean_dir / "main.ts").write_text("/** good play */")
        
        self.stale_dir = FIXTURE_DIR / "stale_play"
        self.stale_dir.mkdir(exist_ok=True)
        (self.stale_dir / "main.ts").write_text("api.openai.com/v1/engines/")
        (self.stale_dir / "deps.toml").write_text('command = "non_existent_tool_12345"\n')

    def capture_run(self, play_uri_arg):
        class Args:
            play_uri = play_uri_arg
            format = "json"
            cmd = "inspect"
            
        old_stdout = sys.stdout
        from io import StringIO
        stream = StringIO()
        sys.stdout = stream
        try:
            play_drift.inspect_drift(Args)
        finally:
            sys.stdout = old_stdout
            
        return json.loads(stream.getvalue())

    def test_clean_play(self):
        result = self.capture_run(str(self.clean_dir))
        self.assertEqual(result["overall"], "CLEAN")
        self.assertEqual(result["findings"][0]["status"], "CLEAN")

    def test_stale_play(self):
        result = self.capture_run(str(self.stale_dir))
        self.assertEqual(result["overall"], "WARNING")
        
        # Should have dependency finding and API finding
        statuses = [f["status"] for f in result["findings"]]
        self.assertTrue("STALE" in statuses)
        self.assertEqual(len(result["findings"]), 2)

if __name__ == "__main__":
    unittest.main()
