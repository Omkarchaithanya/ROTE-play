import unittest
import subprocess
import json
import tempfile
import os

class TestJSONContract(unittest.TestCase):
    def setUp(self):
        self.trace_data = [
            {
                "event_id": "e1",
                "tool": "read_file",
                "agent": "claude",
                "args": {"path": "/etc/hosts"},
                "effect_inferred": "READ_ONLY"
            }
        ]
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.trace_data, self.temp_file)
        self.temp_file.close()

    def tearDown(self):
        os.remove(self.temp_file.name)

    def test_json_output_flag(self):
        """
        Verify that passing --output=json to Rote completely bypasses the
        human-readable text and outputs only raw JSON from FlowOutput.result()
        """
        result = subprocess.run(
            [
                "rote", "play", "run",
                "plays/tripwire-investigate/main.ts",
                f"trace_file={self.temp_file.name}",
                "--output=json"
            ],
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0, f"Rote failed: {result.stderr}")
        
        stdout_output = result.stdout.strip()
        
        # It must not contain the human formatted string
        self.assertNotIn("TRIPWIRE SECURITY REVIEW", stdout_output)
        
        # It must be valid JSON
        try:
            parsed = json.loads(stdout_output)
        except json.JSONDecodeError as e:
            self.fail(f"Output is not valid JSON: {e}\nOutput was:\n{stdout_output}")
            
        # Verify basic expected keys exist from the investigation output
        self.assertIn("target", parsed)
        self.assertIn("policy_decision", parsed)
        self.assertIn("risk", parsed)

if __name__ == '__main__':
    unittest.main()
