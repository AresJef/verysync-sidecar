"""Draft diagnosis is scoped; ready/dispatch coverage and refusals are strict."""
import copy
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("diagnostic_plan", ROOT / "scripts/select-native-diagnostics.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class DiagnosticSelection(unittest.TestCase):
    def test_original_admission_cleanup_remains_a_focused_linux_gate(self):
        selection = {'draft_labels': ['native-incoming-admission-linux-cleanup']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual({row['package'] for row in rows}, {'linux-amd64-standard'})
        self.assertTrue(all(row['label'] == 'native-incoming-admission-linux-cleanup' and
                            row['target'] == 'configuration_engine' and
                            row['filter'] == 'incoming_admission_cases::native_incoming_request_cap_bounds_saturated_admission_and_preserves_files'
                            for row in rows))
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)
        workflow = (ROOT / '.github/workflows/engine-tests.yml').read_text()
        self.assertEqual(workflow.count('      VERYSYNC_TEST_EXPLICIT_TUNNEL: github-actions-isolated-vm'), 2)

    def test_tracker_requires_six_specialist_commands_and_keeps_original_network_coverage(self):
        selection = {'draft_labels': ['native-official-tracker-registration']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 6)
        self.assertEqual({r['package'] for r in rows}, set(HELPER.PROFILES) - {'windows-386-standard'})
        self.assertTrue(all(r['label'] == 'native-official-tracker-registration' and r['target'] == 'network'
                            and r['filter'] == 'tracker_observation_cases::native_tracker_registers_and_exposes_controlled_disconnect'
                            for r in rows))
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)
        workflow = (ROOT / '.github/workflows/engine-tests.yml').read_text()
        self.assertIn('--test-target network --allow-private-discovery --test-filter actual_', workflow)
        sources = ['tests/network.rs', 'tests/common/network_limit_effects.rs', 'tests/common/local_announcement_cases.rs']
        original = sum(len(re.findall(r'async fn actual_[A-Za-z0-9_]+', (ROOT / p).read_text())) for p in sources)
        self.assertEqual(original, 7)
        block = workflow.split('      - name: Verify explicitly authorized official tracker registration and controlled disconnect\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn("if: matrix.label == 'native-official-tracker-registration'", block)
        self.assertIn('--allow-official-tracker', block)
        self.assertIn("matrix.label != 'native-official-tracker-registration'", workflow)

    def test_current_draft_covers_missing_verdicts_and_changed_signed_dial_api(self):
        selection = {'draft_labels': ['native-dial-missing-original-gates', 'native-dial-concurrency-policy', 'native-temp-advertisement-missing-original-gate']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 7)
        dial = 'native_dial_concurrency_limits_one_device_pending_targets_and_recovers_real_transfer'
        temp = 'native_temporary_index_threshold_controls_partial_block_advertisement'
        self.assertEqual({(r['package'], r['filter']) for r in rows}, {
            ('macos-amd64-standard', dial), ('macos-arm64-standard', dial),
            ('linux-amd64-standard', dial), ('linux-arm64-standard', dial),
            ('windows-amd64-standard', dial), ('windows-arm64-standard', dial),
            ('macos-arm64-standard', temp)})
        self.assertTrue(all(r['target'] == 'configuration_engine' and r['trace'] == '0' for r in rows))
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_core_preferences_run_six_original_cases_per_native_profile(self):
        selection = {'draft_labels': ['native-core-preference-current-contract']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 6)
        self.assertEqual({r['package'] for r in rows}, set(HELPER.PROFILES) - {'windows-386-standard'})
        self.assertTrue(all(r['label'] == 'native-core-preference-current-contract' and r['target'] == 'configuration_engine' for r in rows))
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)
        workflow = (ROOT / '.github/workflows/engine-tests.yml').read_text()
        block = workflow.split('      - name: Verify six original core preference cases on the current native source\n', 1)[1].split('      - name:', 1)[0]
        cases = ['native_general_preferences_preserve_sections_disable_progress_and_change_priority_after_restart', 'native_crash_preferences_preserve_fixed_usage_fields_and_survive_restart', 'native_system_preferences_write_real_event_audit_and_preserve_target_selections', 'native_temporary_retention_scans_expire_only_aged_native_inputs_and_survive_restart', 'native_socks5_proxy_authentication_transfer_and_explicit_disable_preserve_data', 'native_narrow_configuration_reads_preserve_identity_folders_and_state']
        self.assertEqual(re.findall(r'^            (native_[a-z0-9_]+)', block, re.M), cases)
        self.assertIn('set -euo pipefail', block)
        self.assertIn('|| vs_status=$?', block)
        self.assertIn('exit \"$vs_failed\"', block)
        self.assertIn('native core preference command receipt:', block)
        self.assertIn('--test-target configuration_engine --test-filter "$vs_case"', block)
        self.assertIn('vs-current-preferences/$vs_case', block)
        self.assertIn("matrix.label != 'native-core-preference-current-contract'", workflow)
        source = (ROOT / 'tests/configuration_engine.rs').read_text()
        self.assertTrue(all(re.search(r'#\[tokio::test\]\s+async fn ' + case + r'\(', source) for case in cases))

    def test_attribute_filter_draft_uses_four_unix_profiles(self):
        selection = {'draft_labels': ['native-extended-attribute-filter']}
        rows = HELPER.select(self.rows, selection, draft=True)
        expected = {'macos-amd64-standard', 'macos-arm64-standard', 'linux-amd64-standard', 'linux-arm64-standard'}
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({row['package'] for row in rows}, expected)
        case = 'native_extended_attribute_filter_uses_first_rule_and_preserves_files'
        self.assertTrue(all(row['target'] == 'configuration_engine' and row['filter'] == case for row in rows))
        source = (ROOT / 'tests/common/extended_attribute_cases.rs').read_text()
        self.assertIn('async fn ' + case + '(', source)
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_unknown_announcement_probe_is_one_isolated_linux_profile(self):
        selection = {'draft_labels': ['native-pending-announcement-source']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['package'], 'linux-amd64-standard')
        self.assertEqual(row['target'], 'network')
        self.assertEqual(row['filter'], 'probe_pending_device_after_unknown_native_announcement')
        source = (ROOT / 'tests/common/local_announcement_cases.rs').read_text()
        self.assertIn('async fn ' + row['filter'] + '(', source)
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_parent_group_control_is_one_isolated_linux_profile(self):
        selection = {'draft_labels': ['native-parent-group-control']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['package'], 'linux-amd64-standard')
        self.assertEqual(row['target'], 'configuration_engine')
        self.assertEqual(row['filter'], 'native_copy_ownership_from_parent_changes_received_group_and_preserves_data')
        source = (ROOT / 'tests/common/ownership_cases.rs').read_text()
        self.assertIn('async fn ' + row['filter'] + '(', source)
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_receive_permissions_are_one_isolated_linux_profile(self):
        selection = {'draft_labels': ['native-receiver-permissions']}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['package'], 'linux-amd64-standard')
        self.assertEqual(row['target'], 'configuration_engine')
        self.assertEqual(row['filter'], 'native_receiver_permission_selection_controls_actual_file_modes')
        source = (ROOT / 'tests/common/file_permission_cases.rs').read_text()
        self.assertIn('async fn ' + row['filter'] + '(', source)
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_copy_range_observer_is_one_linux_profile(self):
        selection = {"draft_labels": ["native-copy-range-syscalls"]}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['package'], 'linux-amd64-standard')
        self.assertEqual(row['target'], 'configuration_engine')
        self.assertEqual(row['filter'], 'native_copy_range_methods_reuse_old_blocks_and_preserve_bytes')
        source = (ROOT / 'tests/common/copy_range_cases.rs').read_text()
        self.assertIn('async fn ' + row['filter'] + '(', source)
        self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)

    def test_copy_range_attribution_requires_the_owned_thread_and_exact_file(self):
        spec = importlib.util.spec_from_file_location('copy_range_fixture', ROOT / 'scripts/run-native-copy-range-test.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        source = Path('/tmp/isolation/receiver-copy-file-range/copy-range-fixture.bin')
        target = source.with_name('.syncthing.copy-range-fixture.bin.tmp')
        effect = f'copy_file_range(5<{source}>, [0], 6<{target}>, [0], 131072, 0) = 131072'
        unrelated = effect.replace('receiver-copy-file-range', 'unrelated-receiver')
        trace = {
            101: ['clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 102',
                  'clone(child_stack=NULL, flags=SIGCHLD) = 103'],
            102: [effect, unrelated],
            103: [effect],
            104: [effect],
        }
        self.assertEqual(fixture.copies(lambda tid: trace.get(tid, []), 101, source, target.__eq__), [131072])

    def test_metadata_only_owned_draft_keeps_native_plan_for_ready_manual_and_forks(self):
        workflow = (ROOT / '.github/workflows/engine-tests.yml').read_text()
        block = workflow.split('  native-diagnostic-plan:\n', 1)[1].split('    name:', 1)[0]
        expression = block.split('    if: ', 1)[1].strip().replace('&&', ' and ').replace('||', ' or ')
        expression = re.sub(r'!(?!=)', 'not ', expression)
        github = SimpleNamespace(event_name='pull_request', head_ref='ci/windows-packet-observer-feasibility-20261118-01a1ca9b',
            repository='AresJef/verysync-sidecar', event=SimpleNamespace(pull_request=SimpleNamespace(
                draft=True, head=SimpleNamespace(repo=SimpleNamespace(full_name='AresJef/verysync-sidecar')))))
        check = lambda: eval(expression, {'__builtins__': {}}, {'github': github, 'true': True, 'false': False})
        self.assertFalse(check())
        github.event.pull_request.draft = False
        self.assertTrue(check())
        github.event.pull_request.draft = True
        github.event.pull_request.head.repo.full_name = 'external/fork'
        self.assertTrue(check())
        github.event_name = 'workflow_dispatch'
        self.assertTrue(check())
        github.event_name = 'pull_request'
        github.event.pull_request.head.repo.full_name = github.repository
        github.head_ref = 'ci/windows-loopback-header-feasibility-20261118-01a1ca9b'
        self.assertFalse(check())
        github.event.pull_request.draft = False
        self.assertTrue(check())
        github.event.pull_request.draft = True
        github.event.pull_request.head.repo.full_name = 'external/fork'
        self.assertTrue(check())

    def test_controlled_node_draft_excludes_old_native_plan_but_keeps_ready_and_forks(self):
        workflow = (ROOT / '.github/workflows/engine-tests.yml').read_text()
        block = workflow.split('  native-diagnostic-plan:\n', 1)[1].split('    name:', 1)[0]
        expression = block.split('    if: ', 1)[1].strip().replace('&&', ' and ').replace('||', ' or ')
        expression = re.sub(r'!(?!=)', 'not ', expression)
        github = SimpleNamespace(event_name='pull_request', head_ref='test/controlled-acceptance-node-20261118-01a1ca9b',
            repository='AresJef/verysync-sidecar', event=SimpleNamespace(pull_request=SimpleNamespace(
                draft=True, head=SimpleNamespace(repo=SimpleNamespace(full_name='AresJef/verysync-sidecar')))))
        check = lambda: eval(expression, {'__builtins__': {}}, {'github': github, 'true': True, 'false': False})
        self.assertFalse(check())
        github.event.pull_request.draft = False
        self.assertTrue(check())
        github.event.pull_request.draft = True
        github.event.pull_request.head.repo.full_name = 'external/fork'
        self.assertTrue(check())
        github.event_name = 'workflow_dispatch'
        self.assertTrue(check())

    def test_ready_keeps_all_six_admission_commands_after_cleanup_change(self):
        rows = HELPER.select(self.rows, {"draft_labels": ["native-incoming-admission-cap", "native-incoming-admission-linux-cleanup"]}, draft=True)
        self.assertEqual(len(rows), 6)
        self.assertEqual({row["package"] for row in rows}, set(HELPER.PROFILES) - {"windows-386-standard"})
        self.assertTrue(all(row["filter"] == "incoming_admission_cases::native_incoming_request_cap_bounds_saturated_admission_and_preserves_files" for row in rows))

    def test_ready_catalog_keeps_six_progress_interval_cases(self):
        selection = {"draft_labels": ["native-progress-interval-policy"]}
        rows = HELPER.select(self.rows, selection, draft=True)
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(row["filter"] == "progress_interval_cases::native_progress_interval_enables_disables_and_restores_actual_transfer_events" for row in rows))

    def test_owned_functional_drafts_exclude_only_unrelated_native_jobs(self):
        workflow = (ROOT / ".github/workflows/engine-tests.yml").read_text()
        for branch in ["test/native-remote-advertisement-20261118-01a1ca9b",
                       "test/native-sftp-server-identity-20261118-01a1ca9b",
                       "test/native-backend-outage-20261118-01a1ca9b",
                       "test/native-lan-bandwidth-20261118-01a1ca9b",
                       "test/native-local-announcement-20261118-01a1ca9b",
                       "test/macos-local-announcement-address-20261118-01a1ca9b",
                       "test/native-explicit-tunnel-20261118-01a1ca9b",
                       "test/native-folder-concurrency-current-20261118-01a1ca9b",
                       "test/native-progress-interval-20261118-01a1ca9b",
                       "test/native-incoming-admission-cap-20261118-01a1ca9b",
                       "test/native-admission-timeout-stage-20261118-01a1ca9b",
                       "test/native-admission-prepared-index-20261118-01a1ca9b",
                       "test/native-admission-staged-deadlines-20261118-01a1ca9b",
                       "test/native-admission-linux-cleanup-20261118-01a1ca9b",
                       "test/native-admission-readonly-exit-20261118-01a1ca9b",
                       "test/native-admission-reconciled-caller-20261118-01a1ca9b",
                       "test/native-official-tracker-20261118-01a1ca9b",
                       "test/native-missing-policy-evidence-20261118-01a1ca9b",
                       "test/native-core-preferences-current-20261118-01a1ca9b",
                       "test/native-xattr-filter-20261118-01a1ca9b",
                       "test/native-pending-announcement-20261118-01a1ca9b",
                       "test/native-parent-group-control-20261118-01a1ca9b",
                       "test/native-receiver-permissions-20261118-01a1ca9b",
                       "test/native-copy-range-syscalls-20261118-01a1ca9b",
                       "ci/windows-packet-observer-feasibility-20261118-01a1ca9b",
                       "ci/windows-loopback-header-feasibility-20261118-01a1ca9b",
                       "test/controlled-acceptance-node-20261118-01a1ca9b",
                       "ci/api-compatibility-tooling-20261118-01a1ca9b",
                       "test/native-storage-backend-acceptance-20261118-01a1ca9b",
                       "fix/storage-backend-receipt-checker-20261118-01a1ca9b",
                       "ci/darwin-owned-process-read-20261118-01a1ca9b",
                       "ci/win7-default-abi-20261118-01a1ca9b"]:
            github = SimpleNamespace(event_name="pull_request", head_ref=branch,
                repository="AresJef/verysync-sidecar", event=SimpleNamespace(
                    pull_request=SimpleNamespace(draft=True, head=SimpleNamespace(
                        repo=SimpleNamespace(full_name="AresJef/verysync-sidecar")))))
            checked = []
            for job, block in re.findall(r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", workflow):
                conditions = [line[len("    if: "):] for line in block.splitlines()
                              if line.startswith("    if: ")]
                if not conditions or "github.head_ref != 'ci/native-temp-advertisement-20261117-01a1ca9b'" not in conditions[0]:
                    continue
                expression = conditions[0].replace("&&", " and ").replace("||", " or ")
                expression = re.sub(r"!(?!=)", "not ", expression)
                context = {"github": github, "false": False, "true": True}
                self.assertFalse(eval(expression, {"__builtins__": {}}, context), job)
                github.event.pull_request.draft = False
                self.assertTrue(eval(expression, {"__builtins__": {}}, context), job)
                github.event.pull_request.draft = True
                github.event.pull_request.head.repo.full_name = "external/fork"
                actual = eval(expression, {"__builtins__": {}}, context)
                github.head_ref = "unrelated"
                self.assertEqual(actual, eval(expression, {"__builtins__": {}}, context), job)
                github.head_ref = branch
                github.event.pull_request.head.repo.full_name = github.repository
                checked.append(job)
            self.assertEqual(len(checked), 8)

    def test_focused_management_target_prepares_private_interpreter_and_arm_helper_role(self):
        workflow = (ROOT / ".github/workflows/engine-tests.yml").read_text()
        for name, arm_only in [("Prepare private protocol-peer tools for storage and management cases", False),
                               ("Prepare the explicit x64 protocol-peer interpreter on Windows ARM", True)]:
            block = workflow.split(f"      - name: {name}\n", 1)[1].split("\n      - ", 1)[0]
            condition = next(line[len("        if: "):] for line in block.splitlines()
                             if line.startswith("        if: "))
            expression = condition.replace("&&", " and ").replace("||", " or ")
            for target in ["authentication_engine", "local_sync_protocol_engine", "local_sync_runtime_engine", "engine_control"]:
                for package in ["windows-arm64-standard", "windows-amd64-standard", "linux-amd64-standard"]:
                    matrix = SimpleNamespace(target=target, package=package)
                    expected = target != "engine_control" and (not arm_only or package == "windows-arm64-standard")
                    self.assertEqual(bool(eval(expression, {"__builtins__": {}}, {"matrix": matrix})), expected,
                                     f"missing private fixture interpreter: {name} / {target} / {package}")
            if arm_only:
                self.assertIn("architecture: x64", block)
                self.assertIn("update-environment: false", block)
            else:
                self.assertIn("python scripts/prepare-storage-test-environment.py", block)

    def test_legacy_windows_build_sets_target_directory_after_runner_assignment(self):
        workflow = (ROOT / ".github/workflows/platform-matrix.yml").read_text()
        job = workflow.split("  windows-legacy-build:\n", 1)[1].split("  x86-compatibility:\n", 1)[0]
        header, steps = job.split("    steps:\n", 1)
        self.assertNotIn("runner.temp", header)
        self.assertNotIn("CARGO_TARGET_DIR", header)
        self.assertIn('Join-Path $env:RUNNER_TEMP', steps)
        self.assertIn('"CARGO_TARGET_DIR=$targetDirectory" | Out-File -FilePath $env:GITHUB_ENV', steps)

    def test_owned_storage_drafts_run_the_selected_native_matrix(self):
        workflow = (ROOT / ".github/workflows/engine-tests.yml").read_text()
        for branch in ["test/strict-storage-tls-defaults-20261117-01a1ca9b",
                       "test/trusted-https-webdav-20261117-01a1ca9b",
                       "ci/strict-storage-native-execution-20261117-01a1ca9b",
                       "ci/native-stop-diagnostics-20261117-01a1ca9b",
                       "ci/native-boundary-diagnostics-20261117-01a1ca9b",
                       "test/ftp-anonymous-native-20261117-01a1ca9b",
                       "ci/native-temp-advertisement-20261117-01a1ca9b",
                       "test/native-remote-advertisement-20261118-01a1ca9b",
                       "test/native-sftp-server-identity-20261118-01a1ca9b",
                       "test/native-backend-outage-20261118-01a1ca9b",
                       "test/native-lan-bandwidth-20261118-01a1ca9b",
                       "test/native-local-announcement-20261118-01a1ca9b",
                       "test/macos-local-announcement-address-20261118-01a1ca9b",
                       "test/native-explicit-tunnel-20261118-01a1ca9b",
                       "test/native-folder-concurrency-current-20261118-01a1ca9b",
                       "test/native-progress-interval-20261118-01a1ca9b",
                       "test/native-incoming-admission-cap-20261118-01a1ca9b",
                       "test/native-admission-timeout-stage-20261118-01a1ca9b",
                       "test/native-admission-prepared-index-20261118-01a1ca9b",
                       "test/native-admission-staged-deadlines-20261118-01a1ca9b",
                       "test/native-admission-linux-cleanup-20261118-01a1ca9b",
                       "test/native-admission-readonly-exit-20261118-01a1ca9b",
                       "test/native-admission-reconciled-caller-20261118-01a1ca9b",
                       "test/native-official-tracker-20261118-01a1ca9b",
                       "test/native-missing-policy-evidence-20261118-01a1ca9b",
                       "test/native-core-preferences-current-20261118-01a1ca9b"]:
            github = SimpleNamespace(event_name="pull_request", head_ref=branch,
                repository="AresJef/verysync-sidecar", event=SimpleNamespace(
                    pull_request=SimpleNamespace(draft=True, head=SimpleNamespace(
                        repo=SimpleNamespace(full_name="AresJef/verysync-sidecar")))))
            for job in ["native-diagnostic-plan", "windows-folder-opener-diagnosis"]:
                block = workflow.split(f"\n  {job}:\n", 1)[1]
                block = re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]
                condition = next(line[len("    if: "):] for line in block.splitlines()
                                 if line.startswith("    if: "))
                expression = condition.replace("&&", " and ").replace("||", " or ")
                expression = re.sub(r"!(?!=)", "not ", expression)
                self.assertTrue(eval(expression, {"__builtins__": {}}, {"github": github}),
                                f"selected native checks were skipped: {branch} / {job}")

    def setUp(self):
        self.rows = json.loads((ROOT / ".github/native-diagnostic-matrix.json").read_text())
        self.selection = {"draft_labels": ["remote-version-archives", "thumbnail-cache"]}

    def test_draft_includes_all_profiles_for_both_pending_features(self):
        actual = HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(len(actual), 12)
        for label in self.selection["draft_labels"]:
            self.assertEqual(len([r for r in actual if r.get("label") == label]), 6)
        self.assertTrue(all(r in self.rows for r in actual))

    def test_draft_cases_use_six_native_profiles_with_a_full_release_catalog(self):
        self.assertEqual(len(self.rows), 256)
        cases = {
            "draft_cases": [
                {"target": "p2p_three_nodes", "filter": "introducer_cases"},
                {"target": "configuration_engine", "filter": "encrypted_folder_cases"},
            ]
        }
        actual = HELPER.select(self.rows, cases, draft=True)
        self.assertEqual(len(actual), 12)
        for case in cases["draft_cases"]:
            matches = [row for row in actual if all(row[k] == v for k, v in case.items())]
            self.assertEqual({row["package"] for row in matches},
                             set(HELPER.PROFILES) - {"windows-386-standard"})
            self.assertTrue(all(row["trace"] == "0" and "label" not in row for row in matches))
        self.assertEqual(HELPER.select(self.rows, cases, draft=False), self.rows)

    def test_draft_cases_reject_ambiguous_routes_and_invalid_command_arguments(self):
        case = {"target": "p2p_three_nodes", "filter": "introducer_cases"}
        for selection in (
            {"draft_cases": []},
            {"draft_cases": [case, case]},
            {"draft_cases": [case] * 33},
            {"draft_cases": [case | {"filter": "a; b"}]},
            {"draft_cases": [case | {"target": None}]},
            {"draft_cases": [case | {"label": "native-official-tracker-registration"}]},
            {"draft_cases": [case], "draft_labels": ["thumbnail-cache"]},
        ):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                HELPER.select(self.rows, selection, draft=True)

    def test_server_identity_draft_selects_all_six_native_rust_and_core_profiles(self):
        actual = HELPER.select(self.rows, {"draft_labels": ["native-sftp-server-identity"]}, draft=True)
        self.assertEqual(len(actual), 6)
        self.assertEqual(len({row["package"] for row in actual}), 6)
        self.assertTrue(all(row["target"] == "local_sync_protocol_engine" and
                            row["filter"] == "public_sftp_server_identity_reports_actual_wrong_and_matching_host_policies"
                            for row in actual))

    def test_idle_backend_outage_keeps_all_six_native_rust_core_and_peer_roles(self):
        actual = HELPER.select(self.rows, {"draft_labels": ["native-backend-request-outage"]}, draft=True)
        self.assertEqual(len(actual), 6)
        self.assertEqual({row["package"] for row in actual}, set(HELPER.PROFILES) - {"windows-386-standard"})
        self.assertTrue(all(row["target"] == "local_sync_runtime_engine" and
                            row["filter"] == "public_backend_requests_preserve_actual_outage_errors_and_data"
                            for row in actual))

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
        self.assertEqual(len(self.rows), 256)
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
        selection = {"draft_labels": ["native-dial-concurrency-policy", "native-dial-missing-original-gates"]}
        actual = HELPER.select(self.rows, selection, draft=True)
        dials = [row for row in actual if row.get("label") in selection["draft_labels"]]
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

    def test_current_outage_draft_and_previous_cases_keep_six_native_profiles(self):
        for selection, label, target, name in [
            ({"draft_labels": ["native-local-announcement"]}, "native-local-announcement", "network",
             "local_announcement_cases::actual_local_announcements_discover_dynamic_peers_and_stop_after_restart"),
            ({"draft_labels": ["native-lan-bandwidth-inclusion"]}, "native-lan-bandwidth-inclusion", "sync_observation",
             "lan_bandwidth_cases::actual_lan_bandwidth_toggle_changes_enforcement_and_preserves_bytes"),
            ({"draft_labels": ["native-backend-request-outage"]}, "native-backend-request-outage", "local_sync_runtime_engine",
             "public_backend_requests_preserve_actual_outage_errors_and_data"),
            ({"draft_labels": ["native-sftp-server-identity"]}, "native-sftp-server-identity", "local_sync_protocol_engine",
             "public_sftp_server_identity_reports_actual_wrong_and_matching_host_policies"),
            ({"draft_labels": ["native-temporary-index-minimum-policy", "native-temp-advertisement-missing-original-gate"]},
             "native-temporary-index-minimum-policy", "configuration_engine",
             "native_temporary_index_threshold_controls_partial_block_advertisement"),
        ]:
            rows = HELPER.select(self.rows, selection, draft=True)
            self.assertEqual(len(rows), 6)
            self.assertEqual({r["package"] for r in rows}, set(HELPER.PROFILES) - {"windows-386-standard"})
            self.assertTrue(all(r["label"] in selection["draft_labels"] and r["target"] == target and
                                r["filter"] == name and r["trace"] == "0" for r in rows))
            self.assertEqual(HELPER.select(self.rows, selection, draft=False), self.rows)
        self.assertEqual(len(self.rows), 256)

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

    def test_owned_formal_candidate_push_uses_the_complete_diagnostic_catalog(self):
        repo = "AresJef/verysync-sidecar"
        event = {"repository": {"full_name": repo}, "deleted": False,
                 "ref": "refs/heads/ci/formal-candidate/r23-intel-deferred/rc1"}
        draft = HELPER.draft_mode("push", event, repo)
        self.assertFalse(draft)
        self.assertEqual(HELPER.select(self.rows, self.selection, draft=draft), self.rows)
        for invalid in (
            event | {"ref": "refs/heads/main"},
            event | {"ref": "refs/heads/ci/formal-candidate/"},
            event | {"deleted": True},
            event | {"repository": {"full_name": "fork/verysync-sidecar"}},
            event | {"repository": "AresJef/verysync-sidecar"},
            event | {"ref": None},
        ):
            with self.subTest(event=invalid), self.assertRaises(ValueError):
                HELPER.draft_mode("push", invalid, repo)
        with self.assertRaises(ValueError):
            HELPER.draft_mode("push", event, "fork/verysync-sidecar")

    def test_planning_does_not_mutate_the_catalog(self):
        before = copy.deepcopy(self.rows)
        HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(self.rows, before)


if __name__ == "__main__":
    unittest.main()
