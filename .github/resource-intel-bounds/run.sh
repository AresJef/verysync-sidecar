#!/usr/bin/env bash
set -euo pipefail
umask 077

harness="$PWD/.github/resource-intel-bounds"
evidence="$RUNNER_TEMP/vs-intel-resource-bounds"

case "$1" in
    calibrate)
        test "$RUNNER_ARCH" = X64
        test "$(/usr/bin/uname -m)" = x86_64
        test "$(/usr/sbin/sysctl -n machdep.cpu.vendor)" = GenuineIntel
        test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
        test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
        mkdir "$evidence"
        build="$(mktemp -d "$RUNNER_TEMP/vs-intel-bounds-bin.XXXXXXXX")"
        printf 'VERYSYNC_INTEL_BOUNDS_BUILD=%s\n' "$build" >> "$GITHUB_ENV"
        {
            /usr/bin/uname -m
            /usr/sbin/sysctl -n machdep.cpu.brand_string
            /usr/bin/sw_vers
            printf 'ImageVersion=%s\n' "${ImageVersion:-unknown}"
            git show -s --format='%H%n%T'
            shasum -a 256 "$harness/intel-contract.json"
        } > "$evidence/host.txt"
        xcrun clang -std=c11 -O2 -Wall -Wextra -Werror -dynamiclib \
            "$harness/read-peak.c" scripts/darwin-owned-sample.c -o "$build/peak.dylib"
        xcrun clang -std=c11 -O2 -Wall -Wextra -Werror "$harness/probe/rss_worker.c" -o "$build/rss-worker"
        test "$(/usr/bin/lipo -archs "$build/rss-worker")" = x86_64
        test "$(/usr/bin/lipo -archs "$build/peak.dylib")" = x86_64
        shasum -a 256 "$build/peak.dylib" "$build/rss-worker" > "$evidence/observer-binaries.txt"
        PYTHONPATH="$harness/probe" python -B "$harness/calibrate.py" \
            "$build/rss-worker" "$build/peak.dylib" "$evidence/controls"
        python -B "$harness/check_calibration.py" "$evidence/controls/calibration.json" \
            "$evidence/controls/verified-threshold-controls.json"
        cargo +"$TEST_TOOLCHAIN" package --no-verify --locked --offline --target-dir "$build/crate-target"
        python -B "$harness/check_package.py" "$build/crate-target/package/verysync-sidecar-0.1.1.crate" \
            "$GITHUB_SHA" "$evidence/candidate-package.json"
        ;;
    cleanup)
        build="$VERYSYNC_INTEL_BOUNDS_BUILD"
        case "$build" in
            "$RUNNER_TEMP"/vs-intel-bounds-bin.*) ;;
            *) exit 41 ;;
        esac
        test "$(dirname "$build")" = "$RUNNER_TEMP"
        test ! -L "$build"
        rm -rf -- "$build/crate-target"
        rm -f -- "$build/peak.dylib" "$build/rss-worker"
        rmdir "$build"
        test ! -e "$build"
        printf '%s\n' owned_observer_binaries_removed=true > "$evidence/observer-cleanup.txt"
        ;;
    prepare|collect|verify)
        exec python -B "$harness/measure_cycles.py" --stage "$1" --source "$PWD" \
            --expected-source "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \
            --evidence "$evidence/collection" --contract "$harness/intel-contract.json" \
            --peak-library "$VERYSYNC_INTEL_BOUNDS_BUILD/peak.dylib" \
            --cargo "$(command -v cargo)" --toolchain "$TEST_TOOLCHAIN" \
            --report "$evidence/verified-formal.json"
        ;;
    *) exit 2 ;;
esac
