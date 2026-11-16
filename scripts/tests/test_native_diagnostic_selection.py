"""Draft diagnosis is scoped; ready/dispatch coverage and refusals are strict."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("diagnostic_plan", ROOT / "scripts/select-native-diagnostics.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class DiagnosticSelection(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / ".github/native-diagnostic-matrix.json").read_text())
        self.selection = {"draft_labels": ["remote-version-archives", "thumbnail-cache"]}

    def test_draft_includes_all_profiles_for_both_pending_features(self):
        actual = HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(len(actual), 12)
        for label in self.selection["draft_labels"]:
            self.assertEqual(len([r for r in actual if r.get("label") == label]), 6)
        self.assertTrue(all(r in self.rows for r in actual))

    def test_ready_catalog_retains_socks5_auth_transfer_on_all_six_profiles(self):
        selection = {"draft_labels": ["native-socks5-proxy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        proxy = [row for row in actual if row.get("label") == "native-socks5-proxy"]
        self.assertEqual(len(proxy), 6)
        self.assertEqual(len({row["package"] for row in proxy}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_socks5_proxy_authentication_transfer_and_explicit_disable_preserve_data"
                            for row in proxy))

    def test_ready_catalog_retains_real_name_adoption_and_data_on_all_six_profiles(self):
        selection = {"draft_labels": ["remote-device-name-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        names = [row for row in actual if row.get("label") == "remote-device-name-policy"]
        self.assertEqual(len(names), 6)
        self.assertEqual(len({row["package"] for row in names}), 6)
        self.assertEqual(len(actual), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_remote_device_name_policy_uses_global_selection_and_preserves_real_data"
                            for row in names))

    def test_current_manifest_runs_nonempty_native_helpers_on_all_six_profiles(self):
        selection = json.loads((ROOT / ".github/native-diagnostic-selection.json").read_text())
        actual = HELPER.select(self.rows, selection, draft=True)
        helpers = [row for row in actual if row.get("label") == "native-helper-effects"]
        self.assertEqual(len(helpers), 6)
        self.assertEqual(len({row["package"] for row in helpers}), 6)
        self.assertTrue(all(row["target"] == "engine_control" and row["filter"] ==
                            "actual_native_helpers_" for row in helpers))

    def test_current_manifest_requires_native_ftp_disconnect_boundaries_on_all_six_profiles(self):
        selection = json.loads((ROOT / ".github/native-diagnostic-selection.json").read_text())
        actual = HELPER.select(self.rows, selection, draft=True)
        ftp = [row for row in actual if row.get("label") == "ftp-disconnect-recovery"]
        self.assertEqual(len(ftp), 6)
        self.assertEqual(len({row["package"] for row in ftp}), 6)
        self.assertTrue(all(row["target"] == "local_sync_runtime_engine" and row["filter"] ==
                            "public_ftp_" for row in ftp))

    def test_ready_catalog_retains_both_strict_ldap_transport_cases_on_six_profiles(self):
        selection = {"draft_labels": ["ldap-verified-transport"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        ldap = [row for row in actual if row.get("label") == "ldap-verified-transport"]
        self.assertEqual(len(ldap), 6)
        self.assertEqual(len({row["package"] for row in ldap}), 6)
        self.assertTrue(all(row["target"] == "ldap_trusted_ca_engine" and row["filter"] ==
                            "native_trusted_ca_" for row in ldap))

    def test_current_manifest_requires_actual_home_free_space_control_on_six_profiles(self):
        selection = json.loads((ROOT / ".github/native-diagnostic-selection.json").read_text())
        actual = HELPER.select(self.rows, selection, draft=True)
        space = [row for row in actual if row.get("label") == "native-home-free-space-policy"]
        self.assertEqual(len(space), 6)
        self.assertEqual(len({row["package"] for row in space}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_home_free_threshold_blocks_index_updates_and_explicit_reset_recovers"
                            for row in space))

    def test_ready_and_dispatch_preserve_every_original_row(self):
        self.assertEqual(HELPER.select(self.rows, self.selection, draft=False), self.rows)
        self.assertEqual(len(self.rows), 114)
        self.assertEqual(HELPER.select(self.rows, None, draft=True), self.rows)

    def test_current_manifest_requires_actual_temporary_expiry_on_six_profiles(self):
        selection = json.loads((ROOT / ".github/native-diagnostic-selection.json").read_text())
        actual = HELPER.select(self.rows, selection, draft=True)
        age = [row for row in actual if row.get("label") == "native-temporary-retention-policy"]
        self.assertEqual(len(actual), 30)
        self.assertEqual(len(age), 6)
        self.assertEqual(len({row["package"] for row in age}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_temporary_retention_scans_expire_only_aged_native_inputs_and_survive_restart"
                            for row in age))

    def test_unknown_empty_duplicate_and_malformed_selection_refused(self):
        for value in [{"draft_labels": []}, {"draft_labels": ["unknown"]},
                      {"draft_labels": ["thumbnail-cache", "thumbnail-cache"]},
                      {"draft_labels": "thumbnail-cache"}, {}, {"draft_labels": None}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                HELPER.select(self.rows, value, draft=True)

    def test_catalog_injection_unknown_runner_duplicates_and_unbounded_input_refused(self):
        for field, value in [("target", "files_engine; echo bad"), ("filter", "$(bad)"),
                             ("runner", "self-hosted"), ("rust", "wrong-target"),
                             ("trace", "anything"), ("package", "unrelated")]:
            changed = copy.deepcopy(self.rows); changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                HELPER.select(changed, self.selection, draft=False)
        for changed in [[], self.rows + [self.rows[0]], self.rows * 20]:
            with self.assertRaises(ValueError):
                HELPER.select(changed, self.selection, draft=True)

    def test_only_owned_drafts_are_scoped_and_missing_event_state_refuses(self):
        repo = "AresJef/verysync-sidecar"
        event = {"pull_request": {"draft": True, "head": {"repo": {"full_name": repo}}}}
        self.assertTrue(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["draft"] = False
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["draft"] = True
        event["pull_request"]["head"]["repo"] = {"full_name": "fork/verysync-sidecar"}
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["head"]["repo"] = None
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        self.assertFalse(HELPER.draft_mode("workflow_dispatch", {}, repo))
        for malformed in [{}, {"pull_request": {"draft": "true"}}, None]:
            with self.assertRaises(ValueError):
                HELPER.draft_mode("pull_request", malformed, repo)
        with self.assertRaises(ValueError):
            HELPER.draft_mode("push", {}, repo)

    def test_planning_does_not_mutate_the_catalog(self):
        before = copy.deepcopy(self.rows)
        HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(self.rows, before)


if __name__ == "__main__":
    unittest.main()
