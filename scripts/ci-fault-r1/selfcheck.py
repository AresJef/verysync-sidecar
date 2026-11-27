"""Exercise collector failure gates without starting or contacting an engine."""
import argparse
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from collect import (PLAN, Redactor, artifact_guard, capture, case_result, cleanup, git,
                     natural_cases, product_guard, read_json)


def check_selectors(product):
    count = sum(len(natural_cases(row["package_id"])) for row in PLAN["platforms"])
    assert len(PLAN["platforms"]) == 6 and count == 37
    for rule in PLAN["natural"] + PLAN["controlled"]:
        target = product / "tests" / f'{rule["target"]}.rs'
        assert target.is_file(), rule
        qualifier, _, function = rule["selector"].rpartition("::")
        if qualifier:
            inclusion = target.read_text(encoding="utf-8")
            assert f"{qualifier}.rs" in inclusion and f"mod {qualifier}" in inclusion, rule
            target = product / "tests" / "common" / f"{qualifier}.rs"
        assert f'fn {function}(' in target.read_text(encoding="utf-8"), rule
    archive = read_json(product / "releases/verysync-v2.33.2.json")
    binaries = read_json(product / "releases/verysync-v2.33.2-standard-binaries.json")
    older = read_json(product / "releases/verysync-upgrade-test-source-v2.33.1.json")
    for row in PLAN["platforms"]:
        platform = row["package_id"]
        current = next(x for x in archive["packages"] if x["id"] == platform)
        pin = next(x for x in binaries["packages"] if x["id"] == platform)
        upgrade = next(x for x in older["packages"] if x["id"] == platform)
        assert len(pin["binary_sha256"]) == len(upgrade["sha256"]) == 64
        assert current["sha256"] == pin["archive_sha256"] and upgrade["alpha_target"]
        print(platform, pin["archive_sha256"], pin["binary_sha256"], upgrade["sha256"])


def synthetic():
    with TemporaryDirectory(prefix="vss-r1-fixture-") as folder:
        root = Path(folder)
        process_log = root / "nonzero.log"
        source = "print('running 1 test\\ntest marker ... FAILED\\ntest result: FAILED. 0 passed; 1 failed;'); raise SystemExit(7)"
        result = capture([sys.executable, "-c", source], root, None, process_log)
        assert result["exit"] == 7
        assert case_result(process_log, "marker", 7)["status"] == "test_failed"
        zero = root / "zero.log"
        result = capture([sys.executable, "-c", "print('running 0 tests')"], root, None, zero)
        assert result["exit"] == 0 and case_result(zero, "marker", 0)["status"] == "zero_cases"
        assert case_result(root / "absent.log", "marker", 0)["status"] == "missing_log"
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "prepare-test-engine.py").write_text(
            "print('owned test process remains'); raise SystemExit(9)\n", encoding="utf-8")
        cleanup_actual = cleanup(root, {"VERYSYNC_TEST_BINARY": str(root/"owned")}, root, "fault-cleanup")
        assert cleanup_actual["current"]["status"] == "failed"
        assert cleanup_actual["upgrade_source"]["status"] == "not_prepared"
        redact = Redactor()
        secret = "dummy-synthetic-secret"
        assert secret not in redact(f'Authorization: Bearer {secret}\n')
        assert secret not in redact(f'{{"api_key":"{secret}"}}\n')
        assert "-----BEGIN" not in redact("-----BEGIN PRIVATE KEY-----\n")
        assert secret not in redact(secret)
        redact("-----END PRIVATE KEY-----\n")
        assert redact("visible state") == "visible state"
        print("SELF_CHECK passed: nonzero child, zero libtest matches, missing log, failed cleanup, synthetic redaction")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    product_guard(args.product)
    check_selectors(args.product.resolve())
    synthetic()
    if args.package:
        artifact_guard(args.package)
        print("SELF_CHECK passed: exact rebuilt crate matched the frozen byte count and SHA-256")


if __name__ == "__main__":
    main()
