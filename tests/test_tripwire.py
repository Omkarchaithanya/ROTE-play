import contextlib
import io
import json
import tempfile
import unittest
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


class TripwireTests(unittest.TestCase):
    def test_secret_values_are_redacted(self):
        openai_like = "sk-" + "abcdefghijklmnopqrstuvwxyz"
        github_like = "ghp_" + "abcdefghijklmnopqrstuvwxyz"
        payload = tripwire.scrub({"api_key": openai_like, "nested": github_like})
        self.assertEqual(payload["api_key"], "PRESENT")
        self.assertEqual(payload["nested"], "NEVER DISPLAYED")
        self.assertNotIn("sk-", json.dumps(payload))

    def test_clean_classification(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "S0"}], "warnings": []}])
        self.assertEqual(payload["overall"], "S0")

    def test_s1_classification(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "S1"}, {"severity": "S0"}], "warnings": []}])
        self.assertEqual(payload["overall"], "S1")

    def test_s2_classification(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "S2"}, {"severity": "S1"}], "warnings": []}])
        self.assertEqual(payload["overall"], "S2")

    def test_s3_classification(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "S3"}, {"severity": "S2"}], "warnings": []}])
        self.assertEqual(payload["overall"], "S3")

    def test_unknown_does_not_escalate(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "UNKNOWN"}], "warnings": []}])
        self.assertEqual(payload["overall"], "UNKNOWN")

    def test_missing_mcp_config_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "home").mkdir()
            (root / "work").mkdir()
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root / "home"), "TRIPWIRE_WORKSPACE": str(root / "work")}):
                payload = capture_json(tripwire.mcp_census, ns())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["findings"][0]["status"], "missing")

    def test_mcp_credential_present_without_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "home" / ".cursor"
            cfg.mkdir(parents=True)
            token = "ghp_" + "secretsecretsecretsecretsecret"
            (cfg / "mcp.json").write_text('{"mcpServers":{"github":{"command":"node","env":{"GITHUB_TOKEN":"' + token + '"}}}}')
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root / "home"), "TRIPWIRE_WORKSPACE": str(root)}):
                payload = capture_json(tripwire.mcp_census, ns())
        text = json.dumps(payload)
        self.assertEqual(payload["findings"][0]["severity"], "S2")
        self.assertNotIn("ghp_secret", text)
        self.assertIn("PRESENT", text)

    def test_env_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("TOKEN=never-print")
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root / "home"), "TRIPWIRE_WORKSPACE": str(root)}):
                payload = capture_json(tripwire.secret_loci, ns())
        self.assertEqual(payload["findings"][0]["severity"], "S2")
        self.assertNotIn("never-print", json.dumps(payload))

    def test_credential_shaped_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "service.token").write_text("secret")
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root / "home"), "TRIPWIRE_WORKSPACE": str(root)}):
                payload = capture_json(tripwire.secret_loci, ns())
        self.assertTrue(any(item["name"] == "service.token" for item in payload["findings"]))

    def test_missing_github_cli_degrades(self):
        original_which = tripwire.shutil.which
        with mock.patch.object(tripwire.shutil, "which", lambda command: None if command == "gh" else original_which(command)):
            payload = capture_json(tripwire.token_ttl, ns())
        self.assertTrue(any(item["message"] == "gh: NOT INSTALLED" for item in payload["findings"]))

    def test_network_unavailable_degrades(self):
        with mock.patch.object(tripwire, "urlopen", side_effect=OSError("offline")):
            payload = capture_json(tripwire.price_tape, ns())
        self.assertEqual(payload["findings"][0]["status"], "unknown")

    def test_listener_permission_failure_degrades(self):
        with mock.patch.object(tripwire.shutil, "which", lambda command: command), mock.patch.object(tripwire, "run_cmd", lambda argv, timeout=5: (False, "")):
            payload = capture_json(tripwire.listen_surface, ns())
        self.assertEqual(payload["findings"][0]["severity"], "UNKNOWN")

    def test_scope_skip(self):
        payload = capture_json(tripwire.harness_inventory, ns(scope="mcp"))
        self.assertEqual(payload["findings"][0]["status"], "skipped")

    def test_missing_harness_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(Path(tmp) / "home"), "TRIPWIRE_WORKSPACE": tmp}):
                with mock.patch.object(tripwire.shutil, "which", return_value=None):
                    payload = capture_json(tripwire.harness_inventory, ns())
        self.assertTrue(all(item["status"] == "missing" for item in payload["findings"]))

    def test_unreadable_path_reported_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blocked = root / ".config"
            blocked.mkdir()
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(root), "TRIPWIRE_WORKSPACE": str(root / "work")}):
                with mock.patch.object(tripwire, "can_read", lambda path: False if path == blocked else True):
                    payload = capture_json(tripwire.secret_loci, ns())
        self.assertTrue(any(item["status"] == "unknown" for item in payload["findings"]))

    def test_git_leak_probe_detects_credential_shaped_history(self):
        outputs = {
            "--is-inside-work-tree": (True, "true"),
            "--name-only": (True, "src/app.py\n.env\n"),
        }

        def fake_run(argv, timeout=5):
            text = " ".join(argv)
            if "--is-inside-work-tree" in text:
                return outputs["--is-inside-work-tree"]
            if "--name-only" in text:
                return outputs["--name-only"]
            return False, ""

        with mock.patch.object(tripwire.shutil, "which", return_value="git"), mock.patch.object(tripwire, "run_cmd", fake_run):
            payload = capture_json(tripwire.git_leak_probe, ns())
        self.assertEqual(payload["findings"][0]["severity"], "S2")

    def test_apply_false_never_performs_writes(self):
        payload = tripwire.analyze_payloads([{"findings": [{"severity": "S0"}], "warnings": []}])
        args = ns(format="json")
        args.analysis = json.dumps(payload)
        result = capture_json(tripwire.verdict, args)
        self.assertFalse(result["write_contract"]["apply_requested"])
        self.assertEqual(result["write_contract"]["revoke_stale"], "DISABLED")

    def test_json_output_validity(self):
        payload = capture_json(tripwire.emit, "probe", [])
        self.assertTrue(payload["ok"])

    def test_normalized_finding_schema(self):
        finding = tripwire.Finding("probe", "name", "ok", "S0", "test message").as_dict()
        self.assertIn("id", finding)
        self.assertEqual(finding["probe"], "probe")
        self.assertEqual(finding["name"], "name")
        self.assertEqual(finding["status"], "ok")
        self.assertEqual(finding["severity"], "S0")

    def test_demo_run_all_is_valid_and_does_not_leak_fixture_secret(self):
        result = capture_json(tripwire.run_all, ns(demo="true"))
        text = json.dumps(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("example", text)
        self.assertIn(result["overall"], {"S0", "S1", "S2", "S3", "UNKNOWN"})

    def test_demo_fixture_detects_s3_write_risk(self):
        result = capture_json(tripwire.run_all, ns(demo="true"))
        self.assertTrue(any(item["severity"] == "S3" for item in result["findings"]))

    def test_demo_fixture_detects_s2_secret_risk(self):
        result = capture_json(tripwire.run_all, ns(demo="true"))
        self.assertTrue(any(item["severity"] == "S2" for item in result["findings"]))

    def test_synthetic_secret_value_never_leaks_from_end_to_end_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            work = root / "work"
            home.mkdir()
            work.mkdir()
            secret_value = "super-" + "secret-" + "test-" + "value"
            (work / ".env").write_text(f"TEST_API_KEY={secret_value}")
            with mock.patch.dict("os.environ", {"TRIPWIRE_HOME": str(home), "TRIPWIRE_WORKSPACE": str(work)}, clear=False):
                result = capture_json(tripwire.run_all, ns())
        text = json.dumps(result)
        self.assertNotIn(secret_value, text)
        self.assertIn("NEVER DISPLAYED", text)

    def test_baseline_tampered(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ws = Path(tmp)
            (self.ws / ".tripwire_previous.json").write_text(json.dumps({"version": "1.0", "hash": "badhash"}))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(self.ws)}):
                res = tripwire.analyze_payloads([])
                self.assertEqual(res["baseline_status"], "TAMPERED")
                self.assertEqual(res["safe_to_run"]["decision"], "UNKNOWN")

    def test_baseline_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": tmp}):
                res = tripwire.analyze_payloads([])
                self.assertEqual(res["baseline_status"], "UNKNOWN")

    def test_current_exceeds_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 0, "cred_count": 0})
            (self.ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 0, "cred_count": 0, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(self.ws)}):
                payloads = [{"findings": [{"probe": "mcp_census", "status": "ok"}]}]
                res = tripwire.analyze_payloads(payloads)
                self.assertEqual(res["delta"]["authority"], "EXCEEDS_APPROVED")
                self.assertEqual(res["safe_to_run"]["decision"], "BLOCKED")

    def test_current_less_than_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 10, "cred_count": 10})
            (self.ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 10, "cred_count": 10, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(self.ws)}):
                res = tripwire.analyze_payloads([])
                self.assertEqual(res["delta"]["authority"], "LESS_THAN_APPROVED")
        
    def test_baseline_delta_12_to_13(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 10, "cred_count": 2})
            (self.ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 10, "cred_count": 2, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(self.ws)}):
                payloads = [{"findings": [{"probe": "mcp_census", "status": "ok"} for _ in range(11)] + [{"probe": "secret_loci", "status": "ok"} for _ in range(2)]}]
                res = tripwire.analyze_payloads(payloads)
                self.assertEqual(res["delta"]["metrics"]["BASELINE"], 12)
                self.assertEqual(res["delta"]["metrics"]["CURRENT"], 13)
                self.assertEqual(res["delta"]["metrics"]["CHANGE"], 1)
                self.assertEqual(res["delta"]["authority"], "EXCEEDS_APPROVED")
                self.assertEqual(res["safe_to_run"]["decision"], "BLOCKED")
        
    def test_schema_change_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ws = Path(tmp)
            h = tripwire.hash_state({"mcp_count": 1, "cred_count": 0, "mcp_schemas": {"github": "old_hash"}})
            (self.ws / ".tripwire_approved.json").write_text(json.dumps({
                "mcp_count": 1, "cred_count": 0, "mcp_schemas": {"github": "old_hash"}, "hash": h
            }))
            with mock.patch.dict("os.environ", {"TRIPWIRE_WORKSPACE": str(self.ws)}):
                payloads = [{"findings": [{"probe": "mcp_census", "status": "ok", "details": {"tools_fingerprint": {"github": {"fingerprint": "new_hash"}}}}]}]
                res = tripwire.analyze_payloads(payloads)
                self.assertIn("github: old_hash -> new_hash", res["delta"]["schema_drifts"])
                self.assertEqual(res["safe_to_run"]["decision"], "BLOCKED")

    def test_blast_radius_unknown_when_static_probes_omitted(self):
        # When no static findings are passed, blast radius should report UNKNOWN, not LOW
        payload = tripwire.analyze_payloads([])
        self.assertEqual(payload["blast_radius"]["level"], "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
