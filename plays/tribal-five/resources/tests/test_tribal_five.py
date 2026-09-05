import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import tribal_five

class TestTribalFive(unittest.TestCase):
    def capture_run(self):
        class Args:
            format = "json"
            
        old_stdout = sys.stdout
        from io import StringIO
        stream = StringIO()
        sys.stdout = stream
        try:
            tribal_five.inspect_tribal_knowledge(Args)
        finally:
            sys.stdout = old_stdout
            
        return json.loads(stream.getvalue())

    def test_five_questions(self):
        result = self.capture_run()
        findings = result["findings"]
        self.assertEqual(len(findings), 5)
        
        # Verify types
        types = [f["type"] for f in findings]
        self.assertIn("FACT", types)
        self.assertIn("INFERENCE", types)

if __name__ == "__main__":
    unittest.main()
