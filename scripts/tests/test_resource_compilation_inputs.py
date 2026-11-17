"""Frozen identity binds literal external compilation inputs, not just .rs bytes."""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "compilation_metrics", Path(__file__).resolve().parents[1] / "measure-native-resources.py")
METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METRICS)


class CompilationInputIdentity(unittest.TestCase):
    def test_real_git_checkout_keeps_compiled_data_bytes_with_windows_autocrlf(self):
        root = Path(__file__).resolve().parents[2]
        documents = re.findall(r'^#!\[doc = include_str!\("\.\./([^"\n]+)"\)\]',
                               (root / 'src/lib.rs').read_text(), re.MULTILINE)
        self.assertEqual(len(documents), 35)
        for name in documents + ['releases/verysync-v2.33.2.json']:
            blob = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=root)
            checked_out = subprocess.check_output(
                ['git', '-c', 'core.autocrlf=true', 'cat-file', '--filters',
                 '--path=' + name, 'HEAD:' + name], cwd=root)
            self.assertTrue(checked_out == blob,
                            'Windows-style Git checkout changed compiled input bytes: ' + name)

    def fixture(self, root):
        files = {"Cargo.toml": b"manifest", "Cargo.lock": b"lock",
                 "src/lib.rs": b'#![doc = include_str!("../docs/guide.md")]\n'
                               b'const DATA: &str = include_str!("../releases/catalog.json");\n',
                 "docs/guide.md": b"original guide", "releases/catalog.json": b'{"value":1}',
                 "tests/resource_usage_engine.rs": b"resource fixture",
                 "tests/common/managed_fixture.rs": b"managed fixture",
                 "tests/common/resource_faults.rs": b"fault fixture",
                 "tests/common/resource_fixture.rs": b"resource fixture helpers",
                 "scripts/measure-native-resources.py": b"sampler",
                 "scripts/macos-observer-activity.py": b"activity",
                 "scripts/run-isolated-engine-tests.py": b"wrapper"}
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def identity(self, root):
        with patch.object(METRICS, "__file__", str(root / "scripts/measure-native-resources.py")), \
                patch.object(METRICS.subprocess, "check_output", return_value="synthetic-toolchain\n"):
            return METRICS.source_identity(root / "tools/cargo", "1.85.0")["rust_sources_sha256"]

    def test_runtime_catalog_change_cannot_retain_frozen_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            before = self.identity(root)
            (root / "releases/catalog.json").write_bytes(b'{"value":2}')
            self.assertNotEqual(before, self.identity(root))

    def test_rustdoc_compilation_input_change_is_bound_even_when_code_is_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            before = self.identity(root)
            (root / "docs/guide.md").write_bytes(b"changed guide")
            self.assertNotEqual(before, self.identity(root))

    def test_input_bytes_must_be_available_in_the_owned_source_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "releases/catalog.json").unlink()
            with self.assertRaises(OSError):
                self.identity(root)

    def test_dynamic_include_cannot_silently_leave_data_out_of_the_frozen_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "src/lib.rs").write_text('const DATA: &str = include_str!(concat!("../releases/", "catalog.json"));')
            with self.assertRaisesRegex(ValueError, "nonliteral compilation input"):
                self.identity(root)

    def test_included_file_outside_owned_source_cannot_be_frozen(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "owned"
            self.fixture(root)
            (parent / "outside.txt").write_text("outside source")
            (root / "src/lib.rs").write_text('const DATA: &str = include_str!("../../outside.txt");')
            with self.assertRaisesRegex(ValueError, "escapes the owned source tree"):
                self.identity(root)


if __name__ == "__main__":
    unittest.main()
