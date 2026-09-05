import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import token_receipt

FIXTURE_DIR = Path(__file__).parent / "fixtures"

class TestTokenReceipt(unittest.TestCase):
    def setUp(self):
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        
        self.cursor_dir = FIXTURE_DIR / ".cursor" / "logs"
        self.cursor_dir.mkdir(parents=True, exist_ok=True)
        
        usage = {
            "date_range": "2026-08-01 to 2026-08-07",
            "model": "claude-3.5-sonnet",
            "total_tokens": 150000,
            "estimated_cost": 0.45
        }
        (self.cursor_dir / "usage.json").write_text(json.dumps(usage))
        
        self.claude_dir = FIXTURE_DIR / ".claude"
        self.claude_dir.mkdir(parents=True, exist_ok=True)
        (self.claude_dir / "telemetry.json").write_text("{}")
        
        self.empty_dir = FIXTURE_DIR / "empty"
        self.empty_dir.mkdir(parents=True, exist_ok=True)

    def capture_run(self, demo_dir):
        class Args:
            format = "json"
            demo = demo_dir
            
        old_stdout = sys.stdout
        from io import StringIO
        stream = StringIO()
        sys.stdout = stream
        try:
            token_receipt.inspect_receipt(Args)
        finally:
            sys.stdout = old_stdout
            
        return json.loads(stream.getvalue())

    def test_found_logs(self):
        result = self.capture_run(str(FIXTURE_DIR))
        findings = result["findings"]
        self.assertEqual(len(findings), 2)
        cursor = next(f for f in findings if f["source"] == "Cursor")
        self.assertEqual(cursor["status"], "KNOWN")
        self.assertEqual(cursor["usage"], "150000 tokens")
        self.assertEqual(cursor["estimated_cost"], "$0.45")

    def test_missing_logs(self):
        result = self.capture_run(str(self.empty_dir))
        findings = result["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "NOT AVAILABLE")

if __name__ == "__main__":
    unittest.main()
