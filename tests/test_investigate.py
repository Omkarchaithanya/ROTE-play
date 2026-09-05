import unittest
import subprocess
import os
from pathlib import Path

class TestInvestigate(unittest.TestCase):
    def setUp(self):
        self.script = Path(__file__).parent.parent / "scripts" / "tripwire.py"
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.env = os.environ.copy()
        self.env["TRIPWIRE_DEMO_ACTIVE"] = "1"
        self.env["TRIPWIRE_WORKSPACE"] = str(self.fixtures_dir / "demo" / "workspace")
        self.env["TRIPWIRE_HOME"] = str(self.fixtures_dir / "demo" / "home")

    def run_investigate(self, trace_file):
        cmd = ["python3", str(self.script), "--demo", "true", "investigate", str(trace_file)]
        # Use python if python3 is not available
        try:
            subprocess.run(["python3", "--version"], capture_output=True, check=True)
        except Exception:
            cmd[0] = "python"
        
        result = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        return result.stdout

    def test_benign_trace(self):
        trace = self.fixtures_dir / "play_test_benign.json"
        output = self.run_investigate(trace)
        self.assertIn("TRIPWIRE Behavioral Investigation", output)
        self.assertNotIn("Policy Decision:\n  BLOCKED", output)
        self.assertTrue("Policy Decision:\n  SAFE" in output or "Policy Decision:\n  REVIEW" in output)

    def test_suspicious_trace(self):
        trace = self.fixtures_dir / "play_test_suspicious.json"
        output = self.run_investigate(trace)
        self.assertIn("TRIPWIRE Behavioral Investigation", output)
        self.assertIn("Policy Decision:\n  BLOCKED", output)
        self.assertIn("Suspicious credential-to-network behavior violates policy", output)

    def test_mutation_trace(self):
        trace = self.fixtures_dir / "play_test_mutation.json"
        output = self.run_investigate(trace)
        self.assertIn("TRIPWIRE Behavioral Investigation", output)
        self.assertTrue("Policy Decision:\n  SAFE" in output or "Policy Decision:\n  REVIEW" in output or "Policy Decision:\n  BLOCKED" in output)

    def test_missing_trace_file(self):
        trace = self.fixtures_dir / "does_not_exist.json"
        cmd = ["python3", str(self.script), "--demo", "true", "investigate", str(trace)]
        try:
            subprocess.run(["python3", "--version"], capture_output=True, check=True)
        except Exception:
            cmd[0] = "python"
        result = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Target trace file not found", result.stderr)

if __name__ == "__main__":
    unittest.main()
