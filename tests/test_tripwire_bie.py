import unittest
import json
import os
from pathlib import Path

from scripts.bie import BehaviorEvent, Investigator, SafeProbe, ProbeCategory

class TestBIEAdversarial(unittest.TestCase):
    def setUp(self):
        self.ref_baseline = {
            "mcp_schemas": {
                "cloudflare": "hash1",
                "aws": "hash2"
            }
        }
        self.current_state = {
            "schema_drifts": []
        }
        
    def test_case_a_misleading_tool_name(self):
        # Case A: read_deployment_status must not automatically become an external write
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "read_deployment_status", {}, "READ_ONLY")
        ]
        result = investigator.run_investigation(events)
        
        self.assertTrue(any("Read-only semantics verified despite dangerous naming" in ev["obs"] for ev in result["evidence"]))
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["policy_decision"], "SAFE")

    def test_case_c_permission_expansion_no_behavior_change(self):
        # Case C: Baseline has new schema, but behavior is unchanged
        self.ref_baseline["mcp_schemas"]["new_tool"] = "hash_new"
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "cloudflare", {}, "READ_ONLY")
        ]
        result = investigator.run_investigation(events)
        self.assertTrue(any("Behavior matches baseline" in ev["obs"] for ev in result["evidence"]))
        self.assertEqual(result["risk"], "LOW")

    def test_case_d_behavior_expansion_no_permission_change(self):
        # Case D: Same permissions, but brand new behavior sequence
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "aws", {}, "EXTERNAL_WRITE")
        ]
        result = investigator.run_investigation(events)
        self.assertIn("H1", [h["id"] for h in result["hypotheses"] if h["conf"] >= 0.4])
        self.assertEqual(result["risk"], "LOW")

    def test_case_b_benign_behavioral_change(self):
        # A legitimate workflow introduces a new read-only tool
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "some_new_read_tool", {}, "READ_ONLY")
        ]
        result = investigator.run_investigation(events)
        
        self.assertTrue(any("New tools observed" in ev["obs"] for ev in result["evidence"]))
        # Risk remains low, but anomalous
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["policy_decision"], "SAFE")

    def test_case_e_schema_mutation(self):
        # Case E: schema mutation
        self.current_state["schema_drifts"] = ["agent-01: hash1 -> hash3"]
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "cloudflare", {}, "UNKNOWN")
        ]
        result = investigator.run_investigation(events)
        
        self.assertTrue(any("Schema changed from baseline" in ev["obs"] for ev in result["evidence"]))
        self.assertIn("H4", [h["id"] for h in result["hypotheses"] if h["conf"] >= 0.4])
        self.assertIn(result["risk"], ["MEDIUM", "HIGH"])
        
    def test_case_f_suspicious_capability_chain(self):
        # Case F: credential_read -> network_request -> external_write
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "read_credential", {}, "READ_ONLY"),
            BehaviorEvent("e2", "agent-01", "send_network_request", {}, "EXTERNAL_WRITE")
        ]
        result = investigator.run_investigation(events)
        
        self.assertIn("Suspicious credential-to-network chain", result["anomalies"])
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["policy_decision"], "BLOCKED")
        
    def test_case_g_ambiguous_evidence(self):
        # Case G: noisy/ambiguous evidence doesn't manufacture certainty
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [
            BehaviorEvent("e1", "agent-01", "normal_read", {}, "READ_ONLY")
        ]
        result = investigator.run_investigation(events)
        
        # Max confidence shouldn't skyrocket to 1.0 for anomaly hypotheses
        for h in result["hypotheses"]:
            if h["id"] in ["H3", "H4"]:
                self.assertLessEqual(h["conf"], 0.5)

    def test_case_h_repeated_benign_behavior(self):
        # Case H: Repeated benign behavior
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [BehaviorEvent("e1", "agent-01", "normal_read", {}, "READ_ONLY") for _ in range(10)]
        result = investigator.run_investigation(events)
        self.assertEqual(result["risk"], "LOW")

    def test_case_j_adversarial_naming(self):
        # Case J: Deliberately misleading names
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        events = [BehaviorEvent("e1", "agent-01", "hack_database", {}, "READ_ONLY")]
        result = investigator.run_investigation(events)
        # BIE doesn't magically panic based on name alone
        self.assertEqual(result["risk"], "LOW")

    def test_case_i_probe_safety(self):
        # Case I: Verify every automatically selected probe is read-only
        investigator = Investigator("agent-01", self.ref_baseline, self.current_state)
        investigator.run_investigation([])
        
        for p in investigator.probes:
            # We enforce that all built-in probes are in specific safe categories
            self.assertIn(p.type, [
                ProbeCategory.SCHEMA_INSPECTION, 
                ProbeCategory.BASELINE_COMPARISON,
                ProbeCategory.ADAPTER_METADATA_INSPECTION
            ])

if __name__ == '__main__':
    unittest.main()
