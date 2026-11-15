"""Explicit custom-std opt-in and transparent Cargo argument contracts."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "cargo-mips-std.py"
SPEC = importlib.util.spec_from_file_location("cargo_mips_std", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class CustomStdContracts(unittest.TestCase):
    def environment(self, target="mips-unknown-linux-gnu"):
        return {"VERYSYNC_TEST_CUSTOM_STD": "rust185-mips-bootstrap",
                "RUSTC_BOOTSTRAP": "1", "CARGO_BUILD_TARGET": target}

    def test_only_explicit_frozen_mode_can_enable_custom_std(self):
        for key in ["VERYSYNC_TEST_CUSTOM_STD", "RUSTC_BOOTSTRAP", "CARGO_BUILD_TARGET"]:
            env = self.environment()
            env.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):
                HELPER.cargo_arguments(["+1.85.0", "check"], env)

    def test_all_four_targets_keep_cargo_arguments_and_select_one_std_build(self):
        for target in ["mips-unknown-linux-gnu", "mipsel-unknown-linux-gnu",
                       "mips64-unknown-linux-gnuabi64", "mips64el-unknown-linux-gnuabi64"]:
            for command in ["build", "check", "test"]:
                args = ["+1.85.0", command, "--locked", "--message-format=json"]
                actual = HELPER.cargo_arguments(args, self.environment(target))
                self.assertEqual(actual, args[:2] + ["-Zbuild-std=std,panic_unwind"] + args[2:])

    def test_other_targets_compilers_and_commands_are_refused(self):
        for args, env in [
            (["+1.99.1", "build"], self.environment()),
            (["+1.85.0", "run"], self.environment()),
            (["+1.85.0", "build"], self.environment("s390x-unknown-linux-gnu")),
            (["test"], self.environment()),
            ([], self.environment()),
        ]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                HELPER.cargo_arguments(args, env)

    def test_target_overrides_cannot_escape_the_declared_profile(self):
        for target in ["x86_64-unknown-linux-gnu", "mipsel-unknown-linux-gnu"]:
            for override in [["--target", target], ["--target=" + target]]:
                with self.assertRaises(ValueError):
                    HELPER.cargo_arguments(["+1.85.0", "check", *override], self.environment())
        args = ["+1.85.0", "check", "--target", "mips-unknown-linux-gnu"]
        self.assertEqual(HELPER.cargo_arguments(args, self.environment())[3:], args[2:])

    def test_conflicting_unstable_options_and_incomplete_targets_are_refused(self):
        for extra in [["-Zbuild-std=core"], ["-Z", "build-std=core"], ["--target"]]:
            with self.assertRaises(ValueError):
                HELPER.cargo_arguments(["+1.85.0", "test", *extra], self.environment())

    def test_binary_arguments_are_not_reinterpreted_as_cargo_options(self):
        args = ["+1.85.0", "test", "--test", "engine_control", "--",
                "--test-threads=1", "--nocapture", "-Zliteral-filter", "--target", "literal-filter"]
        actual = HELPER.cargo_arguments(args, self.environment())
        self.assertEqual(actual, args[:2] + ["-Zbuild-std=std,panic_unwind"] + args[2:])


if __name__ == "__main__":
    unittest.main()
