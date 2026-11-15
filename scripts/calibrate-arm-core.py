"""Explicit CI-only version observations; never platform acceptance."""
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time

CAPTURE_LIMIT = 65536
CPU_MODELS = ("arm926", "arm1176", "cortex-a7")


def capture_version(command, child_env, state, timeout=12):
    # Match the Rust metadata helper: private session, stderr controlling PTY,
    # bounded regular-file stdout and child-only signal/resource settings.
    import fcntl
    import pty
    import resource
    import termios

    master, slave = pty.openpty()
    os.set_blocking(master, False)
    process = None
    timed_out = False
    exceeded = False

    def prepare_child():
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, [])
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        fcntl.ioctl(2, termios.TIOCSCTTY, 0)

    try:
        with tempfile.TemporaryFile(dir=state) as capture:
            process = subprocess.Popen(command, env=child_env, cwd=state,
                                       stdin=subprocess.DEVNULL, stdout=capture,
                                       stderr=slave, preexec_fn=prepare_child)
            os.close(slave)
            slave = None
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                exceeded = os.fstat(capture.fileno()).st_size > CAPTURE_LIMIT
                remaining = deadline - time.monotonic()
                if exceeded or remaining <= 0:
                    timed_out = remaining <= 0
                    break
                readable, _, _ = select.select([master], [], [], min(0.025, remaining))
                if readable:
                    try:
                        os.read(master, 4096)  # Drain without retaining private diagnostics.
                    except OSError:
                        pass
            if process.poll() is None:
                # This exact unreaped child reserves the PID; never signal by name.
                if os.getpgid(process.pid) != process.pid:
                    raise RuntimeError("metadata child lost its private process group")
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            exceeded |= os.fstat(capture.fileno()).st_size > CAPTURE_LIMIT
            capture.seek(0)
            output = capture.read(CAPTURE_LIMIT + 1)
            versions = re.findall(rb"(?m)^verysync (v[0-9]+\.[0-9]+\.[0-9]+)(?:[ \t]|$)", output)
            matches = versions == [b"v2.33.2"]
            code = process.returncode
            return {"exit_code": code, "termination_signal": -code if code < 0 else None,
                    "version_matches": matches, "timed_out": timed_out,
                    "output_exceeded_bound": exceeded,
                    "version_probe_passed": code == 0 and matches and not timed_out and not exceeded}
    finally:
        if process is not None and process.poll() is None:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            process.kill()
            process.wait(timeout=3)
        if slave is not None:
            os.close(slave)
        os.close(master)


def calibrate(root, core, requested):
    if requested not in CPU_MODELS:
        raise ValueError("CPU is outside the explicit calibration set")
    emulator = (root / "qemu-arm").resolve(strict=True)
    core = core.resolve(strict=True)
    results = []
    launches = (("sdk_registered_exec", [str(core)]),
                ("explicit_emulator_exec", [str(emulator), str(core)]))
    for cpu in CPU_MODELS:
        for execution_path, prefix in launches:
            with tempfile.TemporaryDirectory(prefix="vs-arm-version-", dir=root) as state_text:
                state = Path(state_text)
                for relative in ("tmp", "profile/data", "roaming", "local"):
                    (state / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
                # The SDK writes this before inspecting the selected program.
                descriptor = os.open(state / "appconf.yaml", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as config:
                    config.write("auto_startup: false\n")
                child_env = dict(os.environ, QEMU_CPU=cpu, VSMONITORED="yes")
                child_env.update({"HOME": str(state / "profile"), "TMPDIR": str(state / "tmp"),
                                  "XDG_CONFIG_HOME": str(state / "roaming"),
                                  "XDG_CACHE_HOME": str(state / "local"),
                                  "XDG_DATA_HOME": str(state / "profile" / "data")})
                try:
                    row = capture_version([*prefix, "version", "--home", str(state)], child_env, state)
                except OSError as error:
                    row = {"exit_code": None, "termination_signal": None,
                           "version_matches": False, "timed_out": False,
                           "output_exceeded_bound": False, "version_probe_passed": False,
                           "launch_os_error": error.errno}
                row.update({"cpu": cpu, "requested_cpu": cpu == requested,
                            "execution_path": execution_path, "private_startup_disabled": True,
                            "sdk_runtime_acceptance": False, "minimum_native_isa_verified": False,
                            "core_dumps_enabled": False, "launch_profile": "private_stderr_controlling_pty"})
                results.append(row)
                print(json.dumps(row), flush=True)
    (root / "cpu-version-calibration.json").write_text(json.dumps(results, indent=2) + "\n")
    if not next(row["version_probe_passed"] for row in results
                if row["cpu"] == requested and row["execution_path"] == "sdk_registered_exec"):
        raise RuntimeError("The fixed core did not pass the requested CPU version probe; preserve this unverified target condition")


if __name__ == "__main__":
    if not (os.name == "posix" and Path("/proc/sys/fs/binfmt_misc/qemu-arm").is_file()):
        raise RuntimeError("this explicit probe requires the prepared Linux ARM emulation job")
    calibrate(Path(os.environ["RUNNER_TEMP"]) / "vs-arm-emulator",
              Path(os.environ["VERYSYNC_TEST_BINARY"]), os.environ["QEMU_CPU"])
