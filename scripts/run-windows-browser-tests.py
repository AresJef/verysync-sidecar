#!/usr/bin/env python3
"""Explicit standard-Windows-VM SDK browser acceptance with owned class dispatch."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finish_actors(directory, executable):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    journals = {path.stem: path for suffix in ("*.owned", "*.argv") for path in directory.glob(suffix)}
    if len(journals) > 16 or any(not pid.isdecimal() or not 1 < int(pid) <= 0xffffffff for pid in journals):
        raise ValueError("bounded explicit owned browser actor PIDs required")
    for pid, journal in journals.items():
        handle = kernel.OpenProcess(0x100000 | 0x1000, False, int(pid))
        if not handle:
            if ctypes.get_last_error() == 87:
                continue
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if kernel.WaitForSingleObject(handle, 0) != 0:
                size = wintypes.DWORD(32768)
                image = ctypes.create_unicode_buffer(size.value)
                if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if not os.path.samefile(image.value, executable):
                    raise RuntimeError("journal PID image differs; do not signal unrelated process")
                journal.with_suffix(".stop").write_bytes(b"explicit outer owned browser cleanup")
                if kernel.WaitForSingleObject(handle, 3000) != 0:
                    raise RuntimeError("exact owned browser actor did not exit")
        finally:
            kernel.CloseHandle(handle)
    return {"journaled_exact_actors": len(journals), "all_owned_actor_exits_observed": True}


class WindowsChildJob:
    """Contain Cargo and every child before its first instruction executes."""
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t),
                        ("maximum", ctypes.c_size_t), ("active", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                        ("scheduling", wintypes.DWORD)]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", ctypes.c_uint64 * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "QueryInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CreateToolhelp32Snapshot": ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            "Thread32First": ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
            "Thread32Next": ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
            "OpenThread": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "IsProcessInJob": ([wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            call = getattr(self.kernel, name); call.argtypes = args; call.restype = result
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE.
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close(); raise ctypes.WinError(ctypes.get_last_error())

    def spawn(self, command, env):
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   creationflags=0x00000004)  # CREATE_SUSPENDED.
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            class ThreadEntry(ctypes.Structure):
                _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                            ("tid", wintypes.DWORD), ("pid", wintypes.DWORD),
                            ("priority", wintypes.LONG), ("base", wintypes.LONG),
                            ("flags", wintypes.DWORD)]
            snapshot = self.kernel.CreateToolhelp32Snapshot(4, 0)
            if snapshot == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                entry = ThreadEntry(); entry.size = ctypes.sizeof(entry)
                present = self.kernel.Thread32First(snapshot, ctypes.byref(entry)); ids = []
                while present:
                    if entry.pid == process.pid: ids.append(entry.tid)
                    present = self.kernel.Thread32Next(snapshot, ctypes.byref(entry))
                if len(ids) != 1:
                    raise RuntimeError("one still-suspended owned primary thread required")
                thread = self.kernel.OpenThread(2, False, ids[0])
                if not thread: raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if self.kernel.ResumeThread(thread) != 1:
                        raise RuntimeError("owned primary thread suspension differed")
                finally:
                    self.kernel.CloseHandle(thread)
            finally:
                self.kernel.CloseHandle(snapshot)
        except BaseException:
            self.kernel.TerminateJobObject(self.handle, 1)
            process.kill(); process.wait(timeout=5)
            raise
        return process

    def active_images(self):
        """Read only this exact job; do not enumerate or signal host processes."""
        class ProcessIds(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD),
                        ("pids", ctypes.c_size_t * 128)]
        info = ProcessIds()
        if not self.kernel.QueryInformationJobObject(self.handle, 3, ctypes.byref(info), ctypes.sizeof(info), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.assigned > 128 or info.count > 128:
            raise RuntimeError("owned job diagnostic exceeds bounded process count")
        images = []
        for pid in info.pids[:info.count]:
            handle = self.kernel.OpenProcess(0x1000, False, pid)
            if not handle:
                images.append({"pid": pid, "observation": "unavailable after job snapshot"})
                continue
            try:
                member = wintypes.BOOL()
                if not self.kernel.IsProcessInJob(handle, self.handle, ctypes.byref(member)) or not member.value:
                    images.append({"pid": pid, "observation": "job membership changed"})
                    continue
                size = wintypes.DWORD(32768)
                image = ctypes.create_unicode_buffer(size.value)
                if not self.kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                    images.append({"pid": pid, "observation": "image unavailable"})
                else:
                    images.append({"pid": pid, "image_name": Path(image.value).name})
            finally:
                self.kernel.CloseHandle(handle)
        return images

    def wait_empty(self, seconds):
        class Accounting(ctypes.Structure):
            _fields_ = [("times", ctypes.c_int64 * 4), ("faults", wintypes.DWORD),
                        ("total", wintypes.DWORD), ("active", wintypes.DWORD),
                        ("terminated", wintypes.DWORD)]
        deadline = time.monotonic() + seconds
        while True:
            info = Accounting()
            if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.active == 0: return
            if time.monotonic() >= deadline: raise RuntimeError("owned test job remains active")
            time.sleep(0.01)

    def terminate(self):
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        self.wait_empty(5)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle); self.handle = None


def run_bounded(command, env, log, report):
    job = WindowsChildJob(); process = None; reader = None
    markers = {"native": False, "one_case": False, "read_error": None}
    report["contained_processes_stopped"] = False
    def drain():
        try:
            for line in process.stdout:
                log.write(line); log.flush()
                sys.stdout.buffer.write(line); sys.stdout.buffer.flush()
                markers["native"] |= b"native Windows browser evidence:" in line
                markers["one_case"] |= b"test result: ok. 1 passed; 0 failed; 0 ignored;" in line
        except BaseException as error:
            markers["read_error"] = type(error).__name__
    try:
        process = job.spawn(command, env)
        reader = threading.Thread(target=drain, daemon=True); reader.start()
        report["test_exit_code"] = process.wait(timeout=180)
        reader.join(timeout=5)
        if reader.is_alive() or markers["read_error"]:
            raise RuntimeError("test output drain did not complete")
        if report["test_exit_code"] != 0:
            try:
                report["owned_job_images_after_failure"] = job.active_images()
            except Exception as error:
                report["owned_job_image_diagnostic_error"] = type(error).__name__
        job.wait_empty(3)
        report["owned_job_empty_before_outer_termination"] = True
        report["native_sdk_effects_verified"] = report["test_exit_code"] == 0 and markers["native"] and markers["one_case"]
    finally:
        try:
            job.terminate()
            if process is not None: process.wait(timeout=5)
            if reader is not None:
                reader.join(timeout=5)
                if reader.is_alive(): raise RuntimeError("owned output pipe did not close after containment cleanup")
            report["contained_processes_stopped"] = True
        finally:
            job.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    pilot = load("browser_registry", "probe-windows-browser-associations.py")
    pilot.require_scope(args.evidence_dir, os.environ)
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("explicit standard hosted Windows VM required")
    if not args.cargo.is_absolute() or not args.cargo.is_file():
        raise ValueError("explicit absolute Cargo executable required")
    binary = Path(os.environ["VERYSYNC_TEST_BINARY"])
    if not binary.is_absolute() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != os.environ["VERYSYNC_TEST_BINARY_SHA256"]:
        raise ValueError("fixed task-owned native binary/digest required")
    import winreg
    helper = load("browser_isolation", "run-isolated-engine-tests.py")
    args.evidence_dir.mkdir(mode=0o700)
    report = {"user_choice_modified": False, "machine_association_modified": False,
              "registry_restored": False, "native_sdk_effects_verified": False}
    with helper.BlockedProxy() as proxy:
        server = threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        server.start()
        env = os.environ.copy()
        address = f"http://127.0.0.1:{proxy.server_address[1]}"
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[name] = address
        env["NO_PROXY"] = "127.0.0.1,localhost,::1"
        env["CARGO_NET_OFFLINE"] = "true"
        for key in ("VERYSYNC_TEST_BROWSER_ACTOR", "VERYSYNC_TEST_OPENER_RUNTIME_PROBE", "VERYSYNC_TEST_OPENER_OWNED_CHILD", "VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE", "VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN"):
            env.pop(key, None)
        transaction = None
        opener = None
        try:
            opener = helper.prepare_native_opener(str(args.cargo), args.toolchain, args.evidence_dir, env)
            executable = Path(env["VERYSYNC_TEST_OPENER_EXECUTABLE"])
            # The shared directory fixture uses the special rundll32 filename.
            # Browser associations use the ordinary capture name already proven
            # by the standalone protocol pilot; no directory interception needed.
            browser_capture = executable.with_name("owned browser capture \u03b2.exe")
            executable.rename(browser_capture)
            executable = browser_capture
            if hashlib.sha256(executable.read_bytes()).hexdigest() != opener["sha256"]:
                raise ValueError("browser capture bytes differ from the built artifact")
            report["browser_capture"] = {"name": executable.name,
                                         "sha256": opener["sha256"],
                                         "same_built_bytes_verified": True}
            env["VERYSYNC_TEST_OPENER_EXECUTABLE"] = str(executable)
            env["BROWSER"] = str(executable)
            env["VERYSYNC_TEST_BROWSER_HOLD"] = "1"
            env["VERYSYNC_TEST_BROWSER_ISOLATION"] = "windows-effective-progid-v1"
            transaction = pilot.ProtocolTransaction(winreg, use_effective_progid=True)
            transaction.apply(executable)
            command = [str(args.cargo), "+" + args.toolchain, "test", "--features", "engine-tests",
                       "--test", "browser_engine", "--offline", "--locked",
                       "actual_windows_native_browser", "--", "--test-threads=1", "--nocapture"]
            report["native_sdk_command_started"] = True
            with (args.evidence_dir / "browser-engine.log").open("wb") as log:
                run_bounded(command, env, log, report)
            report["actors"] = finish_actors(Path(env["VERYSYNC_TEST_OPENER_CAPTURE_DIR"]), executable)
        finally:
            try:
                if opener is not None:
                    executable = Path(env["VERYSYNC_TEST_OPENER_EXECUTABLE"])
                    report["final_actors"] = finish_actors(Path(env["VERYSYNC_TEST_OPENER_CAPTURE_DIR"]), executable)
            finally:
                try:
                    if transaction is not None:
                        if not report.get("contained_processes_stopped", True):
                            raise RuntimeError("owned children not stopped; preserve capture mapping and evidence")
                        transaction.restore()
                        report["registry_restored"] = True
                finally:
                    proxy.shutdown(); server.join(timeout=5)
                    report["proxy"] = {"external_forwarding_implemented": False,
                                       "listener_loopback_only": True, "handler_errors": proxy.errors}
                    (args.evidence_dir / "observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                    print("Windows native SDK browser observations: " + json.dumps(report), flush=True)
    if report.get("test_exit_code") != 0 or not report["native_sdk_effects_verified"] or not report["registry_restored"] or proxy.errors:
        return report.get("test_exit_code") or 1
    shutil.rmtree(args.evidence_dir / "owned-native-opener")
    report["owned_capture_removed_after_exit_and_registry_restore"] = True
    (args.evidence_dir / "observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Windows native SDK browser complete: " + json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
