import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
import preflight

class TestPreflight(unittest.TestCase):
    @patch("preflight.run_subplay")
    def test_preflight_overall_classification(self, mock_run_subplay):
        mock_run_subplay.side_effect = [
            {"overall": "S2 SECRET RISK"}, # TRIPWIRE
            {"overall": "CLEAN"}, # PLAY-DRIFT (S0)
            {"overall": "S0"} # WRITE-GUARD-XRAY
        ]
        
        class Args:
            format = "json"
            demo = False
            xray_target = None
            
        old_stdout = sys.stdout
        from io import StringIO
        stream = StringIO()
        sys.stdout = stream
        try:
            preflight.run_preflight(Args)
        finally:
            sys.stdout = old_stdout
            
        result = json.loads(stream.getvalue())
        self.assertEqual(result["overall"], "S2")
        self.assertEqual(mock_run_subplay.call_count, 3)

if __name__ == "__main__":
    unittest.main()
