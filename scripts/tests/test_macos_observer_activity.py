"""A diagnostic activity must preserve scope, exact ownership and cleanup."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SPEC=importlib.util.spec_from_file_location('activity',Path(__file__).resolve().parents[1]/'macos-observer-activity.py')
A=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(A)

class ObserverActivityContracts(unittest.TestCase):
    def test_only_latency_and_user_activity_allowing_idle_sleep_are_requested(self):
        self.assertEqual(A.OPTIONS,0xFF00000000|0x00EFFFFF)
        self.assertEqual(A.OPTIONS&((1<<20)|(1<<40)),0)

    def test_worker_start_is_required_before_any_native_call(self):
        native=Mock();guard=A.ObserverActivity(native)
        with self.assertRaises(ValueError):guard.begin(worker_started=False)
        native.start.assert_not_called()
        guard.close();native.end.assert_not_called()

    def test_native_token_has_exact_single_end_and_never_claims_timer_success(self):
        native=Mock();token=object();native.start.return_value=token
        guard=A.ObserverActivity(native);report=guard.begin(worker_started=True)
        self.assertTrue(report['started']);self.assertFalse(report['ended'])
        self.assertFalse(report['idle_sleep_disabled']);self.assertFalse(report['display_sleep_disabled'])
        self.assertFalse(report['timer_improvement_or_frozen_membership_claimed'])
        with self.assertRaises(ValueError):guard.begin(worker_started=True)
        guard.close();guard.close()
        native.start.assert_called_once_with(A.OPTIONS);native.end.assert_called_once_with(token)
        self.assertTrue(guard.report()['ended'])

    def test_failed_begin_does_not_fabricate_an_activity_or_end_unknown_token(self):
        native=Mock();native.start.side_effect=RuntimeError('synthetic unavailable native activity')
        guard=A.ObserverActivity(native)
        with self.assertRaises(RuntimeError):guard.begin(worker_started=True)
        self.assertFalse(guard.report()['started']);guard.close();native.end.assert_not_called()

    def test_forked_or_other_thread_cannot_end_owner_activity(self):
        native=Mock();guard=A.ObserverActivity(native);guard.begin(worker_started=True)
        with patch.object(A.os,'getpid',return_value=-1),self.assertRaises(RuntimeError):guard.close()
        native.end.assert_not_called();guard.close();native.end.assert_called_once()

    def test_measurement_role_is_explicit_and_does_not_claim_dataset_acceptance(self):
        guard=A.ObserverActivity(Mock(),purpose='measurement');guard.begin(worker_started=True)
        self.assertFalse(guard.report()['diagnostic_only']);self.assertEqual(guard.report()['usage_role'],'measurement')
        self.assertFalse(guard.report()['timer_improvement_or_frozen_membership_claimed']);guard.close()
        with self.assertRaises(ValueError):A.ObserverActivity(purpose='unknown')

    def test_native_activity_is_not_available_on_non_macos(self):
        with patch.object(A.sys,'platform','linux'),self.assertRaises(ValueError):A.NativeRuntime()

if __name__=='__main__':unittest.main()
