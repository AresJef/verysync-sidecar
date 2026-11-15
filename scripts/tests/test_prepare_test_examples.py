"""Cargo output contracts for explicit native and cross-compiled examples."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "prepare-test-examples.py"
SPEC = importlib.util.spec_from_file_location("prepare_test_examples", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class CargoArtifactContracts(unittest.TestCase):
    def test_actual_cross_target_executable_is_retained_without_guessing_host_directory(self):
        executable = str(Path("explicit target") / "armv7-unknown-linux-gnueabihf" /
                         "debug" / "examples" / "manage_owned")
        messages = [{"reason": "compiler-artifact", "target": {"kind": ["lib"], "name": "dependency"},
                     "executable": None},
                    {"reason": "compiler-artifact", "target": {"kind": ["example"], "name": "manage_owned"},
                     "executable": executable},
                    {"reason": "build-finished", "success": True}]
        result = SimpleNamespace(returncode=0, stdout="\n".join(map(json.dumps, messages)), stderr="")
        with patch.object(HELPER.subprocess, "run", return_value=result) as run:
            artifacts = HELPER.build_artifacts(["cargo", "+1.85.0"], ["--examples"])
        self.assertEqual(artifacts, {"manage_owned": Path(executable)})
        self.assertIn("--message-format=json", run.call_args.args[0])

    def test_failed_cargo_build_cannot_export_apparently_successful_artifacts(self):
        message = {"reason": "compiler-message", "message": {"rendered": "synthetic compile failure\n"}}
        result = SimpleNamespace(returncode=101, stdout=json.dumps(message), stderr="")
        output = io.StringIO()
        with patch.object(HELPER.subprocess, "run", return_value=result), contextlib.redirect_stderr(output):
            with self.assertRaises(subprocess.CalledProcessError):
                HELPER.build_artifacts(["cargo", "+1.85.0"], ["--examples"])
        self.assertEqual(output.getvalue(), "synthetic compile failure\n")


if __name__ == "__main__":
    unittest.main()
