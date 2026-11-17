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

    def test_ready_catalog_retains_nonempty_native_helpers_on_all_six_profiles(self):
        selection = {"draft_labels": ["native-helper-effects"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        helpers = [row for row in actual if row.get("label") == "native-helper-effects"]
        self.assertEqual(len(helpers), 6)
        self.assertEqual(len({row["package"] for row in helpers}), 6)
        self.assertTrue(all(row["target"] == "engine_control" and row["filter"] ==
                            "actual_native_helpers_" for row in helpers))

    def test_ready_catalog_retains_native_ftp_disconnect_boundaries_on_all_six_profiles(self):
        selection = {"draft_labels": ["ftp-disconnect-recovery"]}
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

    def test_ready_catalog_retains_actual_home_free_space_control_on_six_profiles(self):
        selection = {"draft_labels": ["native-home-free-space-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        space = [row for row in actual if row.get("label") == "native-home-free-space-policy"]
        self.assertEqual(len(space), 6)
        self.assertEqual(len({row["package"] for row in space}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_home_free_threshold_blocks_index_updates_and_explicit_reset_recovers"
                            for row in space))

    def test_ready_and_dispatch_preserve_every_original_row(self):
        self.assertEqual(HELPER.select(self.rows, self.selection, draft=False), self.rows)
        self.assertEqual(len(self.rows), 163)
        self.assertEqual(HELPER.select(self.rows, None, draft=True), self.rows)

    def test_ready_catalog_retains_priority_and_windows_sharing_effects(self):
        selection = {"draft_labels": ["native-priority-queue", "native-link-producer-win386",
                                      "native-kernel-upload-windows"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        priority = [row for row in actual if row.get("label") == "native-priority-queue"]
        self.assertEqual({row["package"] for row in priority}, set(HELPER.PROFILES) - {"windows-386-standard"})
        self.assertEqual(len(priority), 6)
        self.assertTrue(all(row["target"] == "sync_observation" and row["filter"] ==
                            "actual_folder_order_and_specific_priority_change_preserve_samples"
                            for row in priority))
        producer = [row for row in actual if row.get("label") == "native-link-producer-win386"]
        self.assertEqual(len(producer), 1)
        self.assertEqual(producer[0]["package"], "windows-386-standard")
        self.assertEqual(producer[0]["target"], "engine_control")
        self.assertEqual(producer[0]["filter"],
                         "actual_native_helpers_consume_official_add_url_before_native_start_refusal")
        uploads = [row for row in actual if row.get("label") == "native-kernel-upload-windows"]
        self.assertEqual({row["package"] for row in uploads},
                         {"windows-amd64-standard", "windows-arm64-standard"})
        self.assertEqual(len(uploads), 2)
        self.assertTrue(all(row["target"] == "upgrade_engine" and row["filter"] ==
                            "kernel_streamed_archive_upload_replaces_only_the_owned_old_copy"
                            for row in uploads))

    def test_ready_catalog_retains_actual_temporary_expiry_on_six_profiles(self):
        selection = {"draft_labels": ["native-temporary-retention-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        age = [row for row in actual if row.get("label") == "native-temporary-retention-policy"]
        self.assertEqual(len(actual), 6)
        self.assertEqual(len(age), 6)
        self.assertEqual(len({row["package"] for row in age}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_temporary_retention_scans_expire_only_aged_native_inputs_and_survive_restart"
                            for row in age))

    def test_ready_catalog_retains_actual_macos_sleep_assertion_effects(self):
        selection = {"draft_labels": ["native-sleep-prevention-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        sleep = [row for row in actual if row.get("label") == "native-sleep-prevention-policy"]
        self.assertEqual(len(sleep), 2)
        self.assertEqual({row["package"] for row in sleep},
                         {"macos-amd64-standard", "macos-arm64-standard"})
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_sleep_prevention_tracks_actual_owned_assertions_during_transfer"
                            for row in sleep))

    def test_windows_sleep_requests_have_both_actual_native_profile_gates(self):
        selection = {"draft_labels": ["native-windows-sleep-prevention-policy"]}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual({r["package"] for r in rows}, {"windows-amd64-standard", "windows-arm64-standard"})
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["target"] == "configuration_engine" and r["filter"] ==
                            "native_sleep_prevention_tracks_actual_owned_assertions_during_transfer" for r in rows))

    def test_ready_catalog_retains_real_ordered_folder_concurrency_on_six_profiles(self):
        selection = {"draft_labels": ["native-folder-concurrency-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        folders = [row for row in actual if row.get("label") == "native-folder-concurrency-policy"]
        self.assertEqual(len(actual), 6)
        self.assertEqual(len(folders), 6)
        self.assertEqual(len({row["package"] for row in folders}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_folder_concurrency_has_ordered_single_and_double_sync_effects"
                            for row in folders))

    def test_ready_catalog_retains_pending_tls_dials_and_real_recovery_on_six_profiles(self):
        selection = {"draft_labels": ["native-dial-concurrency-policy"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        dials = [row for row in actual if row.get("label") == "native-dial-concurrency-policy"]
        self.assertEqual(len(actual), 6)
        self.assertEqual(len(dials), 6)
        self.assertEqual(len({row["package"] for row in dials}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_dial_concurrency_limits_one_device_pending_targets_and_recovers_real_transfer"
                            for row in dials))

    def test_ready_catalog_retains_signed_incoming_selections_and_three_real_transfers(self):
        selection = {"draft_labels": ["native-signed-incoming-budget"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        budgets = [row for row in actual if row.get("label") == "native-signed-incoming-budget"]
        self.assertEqual(len(actual), 6)
        self.assertEqual(len(budgets), 6)
        self.assertEqual(len({row["package"] for row in budgets}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_signed_incoming_request_budgets_survive_restart_and_real_transfers"
                            for row in budgets))

    def test_ready_catalog_retains_native_general_signed_domains_on_all_six_profiles(self):
        selection = {"draft_labels": ["native-general-signed-domains"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        domains = [row for row in actual if row.get("label") == "native-general-signed-domains"]
        self.assertEqual(len(actual), 6)
        self.assertEqual(len(domains), 6)
        self.assertEqual(len({row["package"] for row in domains}), 6)
        self.assertTrue(all(row["target"] == "configuration_engine" and row["filter"] ==
                            "native_general_signed_integer_domains_survive_partial_full_saves_and_restart"
                            for row in domains))

    def test_catalog_keeps_six_concurrency_cases_and_owned_win386_producer(self):
        selection = {"draft_labels": ["native-folder-concurrency-policy", "native-link-producer-win386"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(actual), 7)
        folders = [row for row in actual if row["label"] == "native-folder-concurrency-policy"]
        self.assertEqual(len(folders), 6)
        self.assertEqual({row["package"] for row in folders},
                         set(HELPER.PROFILES) - {"windows-386-standard"})
        producer = [row for row in actual if row["label"] == "native-link-producer-win386"]
        self.assertEqual(len(producer), 1)
        self.assertEqual(producer[0]["package"], "windows-386-standard")
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_current_draft_selects_six_actual_full_index_upgrade_policy_cases(self):
        selection = json.loads((ROOT / ".github/native-diagnostic-selection.json").read_text())
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 6)
        self.assertEqual({r["package"] for r in rows},
                         set(HELPER.PROFILES) - {"windows-386-standard"})
        self.assertTrue(all(r["target"] == "upgrade_engine" and r["filter"] ==
                            "native_full_index_upgrade_policy_changes_actual_unchanged_index_resend" for r in rows))
        self.assertEqual(len(HELPER.select(self.rows, selection, draft=False)), 163)

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
