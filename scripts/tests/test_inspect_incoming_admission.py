"""Reject incomplete admission evidence instead of interpreting retained memory."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("admission", Path(__file__).resolve().parents[1] / "inspect-incoming-admission.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def bundle(*, admitted=256, waiting=512, cap=32768, wait_frame=True):
    options = {"maxConcurrentIncomingRequestKiB": cap, "maxSendKbps": 1, "limitBandwidthInLan": True}
    options.update({field: False for field in HELPER.DISABLED_FIELDS})
    frames = "# model.(*requestResponse).Wait\n" if wait_frame else ""
    profile = f"goroutine profile: total 900\n{admitted} @ 0x1 0x2\n{frames}# model.newLimitedRequestResponse.func1\n\n{waiting} @ 0x3 0x4\n# semaphore.(*Semaphore).takeInner\n# model.newLimitedRequestResponse\n"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("config.json.txt", json.dumps({"options": options}))
        archive.writestr("version-platform.json.txt", json.dumps({"version": "v2.33.2"}))
        archive.writestr("verysync-goroutine-test.txt", profile)
    output.seek(0)
    return output


class IncomingAdmission(unittest.TestCase):
    def test_first_stack_after_profile_header_is_counted(self):
        result = HELPER.inspect_bundle(bundle(), 32768)
        self.assertEqual(result["admitted_bytes"], 32 * 1024 * 1024)
        self.assertEqual(result["waiting_for_admission_count"], 512)
        self.assertNotIn("stacks", result)

    def test_larger_configured_cap_requires_twice_the_admission(self):
        result = HELPER.inspect_bundle(bundle(admitted=512, waiting=256, cap=65536), 65536)
        self.assertEqual(result["admitted_bytes"], 64 * 1024 * 1024)

    def test_unsaturated_or_excess_admission_is_rejected(self):
        for count in (0, 60, 255, 257, 512):
            with self.subTest(count=count), self.assertRaises(ValueError):
                HELPER.inspect_bundle(bundle(admitted=count), 32768)

    def test_no_waiting_demand_cannot_prove_a_saturated_cap(self):
        with self.assertRaises(ValueError):
            HELPER.inspect_bundle(bundle(waiting=0), 32768)

    def test_callback_without_completion_wait_is_rejected(self):
        with self.assertRaises(ValueError):
            HELPER.inspect_bundle(bundle(wait_frame=False), 32768)

    def test_wrong_native_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            HELPER.inspect_bundle(bundle(cap=65536), 32768)

    def test_duplicate_or_unsafe_profile_name_is_rejected(self):
        data = bundle()
        with zipfile.ZipFile(data, "a") as archive:
            archive.writestr("../outside.txt", "private")
        data.seek(0)
        with self.assertRaises(ValueError):
            HELPER.inspect_bundle(data, 32768)


if __name__ == "__main__":
    unittest.main()
