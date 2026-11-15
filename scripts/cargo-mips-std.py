#!/usr/bin/env python3
"""Explicit CI-only frozen Rust 1.85 MIPS custom-std Cargo adapter."""
import os
import shutil
import sys

TARGETS = frozenset({
    "mips-unknown-linux-gnu", "mipsel-unknown-linux-gnu",
    "mips64-unknown-linux-gnuabi64", "mips64el-unknown-linux-gnuabi64",
})


def cargo_arguments(arguments, environment):
    if (environment.get("VERYSYNC_TEST_CUSTOM_STD") != "rust185-mips-bootstrap"
            or environment.get("RUSTC_BOOTSTRAP") != "1"
            or environment.get("CARGO_BUILD_TARGET") not in TARGETS):
        raise ValueError("explicit frozen MIPS custom-std environment is required")
    if (len(arguments) < 2 or arguments[0] != "+1.85.0"
            or arguments[1] not in {"build", "check", "test"}):
        raise ValueError("only explicit Rust 1.85 build/check/test commands are accepted")
    cargo_options = arguments[2:]
    if "--" in cargo_options:
        cargo_options = cargo_options[:cargo_options.index("--")]
    for index, option in enumerate(cargo_options):
        if option.startswith("-Z"):
            raise ValueError("conflicting unstable Cargo flags are refused")
        if option == "--target":
            if (index + 1 == len(cargo_options)
                    or cargo_options[index + 1] != environment["CARGO_BUILD_TARGET"]):
                raise ValueError("Cargo target must match the explicit MIPS profile")
        elif option.startswith("--target="):
            if option.split("=", 1)[1] != environment["CARGO_BUILD_TARGET"]:
                raise ValueError("Cargo target must match the explicit MIPS profile")
    return [*arguments[:2], "-Zbuild-std=std,panic_unwind", *arguments[2:]]


def main():
    arguments = cargo_arguments(sys.argv[1:], os.environ)
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("the explicit Rust toolchain requires Cargo on PATH")
    # This adapter neither enables bootstrap itself nor changes any Cargo config.
    # It only forwards an already opted-in command; no official core is started.
    os.execv(cargo, ["cargo", *arguments])


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from None
