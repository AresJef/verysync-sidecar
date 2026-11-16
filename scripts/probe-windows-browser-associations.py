#!/usr/bin/env python3
"""Explicit isolated-Windows-CI protocol pilot; never invokes VerySync."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

PROTOCOLS = ("http", "https")
CLASSES = r"Software\Classes"


def require_scope(directory, env):
    if sys.platform != "win32" or env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_OS") != "Windows":
        raise ValueError("explicit isolated GitHub Windows VM required")
    temporary = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    if not directory.is_absolute() or not directory.parent.resolve(strict=True).is_relative_to(temporary):
        raise ValueError("fresh pilot directory inside the runner temporary root required")
    if directory.exists():
        raise ValueError("pilot directory must not already exist")


def shell_functions():
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    query = ctypes.WinDLL("shlwapi", use_last_error=True).AssocQueryStringW
    query.argtypes = [wintypes.DWORD, ctypes.c_int, wintypes.LPCWSTR, wintypes.LPCWSTR,
                      wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    query.restype = ctypes.c_long
    shell.SHChangeNotify.argtypes = [ctypes.c_long, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p]
    shell.SHChangeNotify.restype = None
    return shell, query


def effective_handler(protocol):
    _, query = shell_functions()
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    # ASSOCF_IS_PROTOCOL maps current user defaults; ASSOCSTR_EXECUTABLE = 2.
    status = query(0x1000, 2, protocol, "open", buffer, ctypes.byref(size))
    return buffer.value if status == 0 else None


def notify_associations():
    shell, _ = shell_functions()
    shell.SHChangeNotify(0x08000000, 0, None, None)


def tree_snapshot(reg, path, budget=None):
    if budget is None:
        budget = [64, 65536]
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ)
    except FileNotFoundError:
        return None
    with key:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError("protocol registry snapshot exceeds key bound")
        subkeys, values, _ = reg.QueryInfoKey(key)
        if values > 64:
            raise ValueError("protocol registry snapshot exceeds value bound")
        items = []
        for i in range(values):
            name, value, kind = reg.EnumValue(key, i)
            encoded = value.hex() if isinstance(value, bytes) else value
            item = [name, kind, encoded]
            budget[1] -= len(json.dumps(item, ensure_ascii=True))
            if budget[1] < 0:
                raise ValueError("protocol registry snapshot exceeds byte bound")
            items.append(item)
        children = {}
        for i in range(subkeys):
            name = reg.EnumKey(key, i)
            children[name] = tree_snapshot(reg, path + "\\" + name, budget)
        return {"values": sorted(items), "children": children}


class ProtocolTransaction:
    def __init__(self, reg):
        self.reg = reg
        self.created = []
        self.values = []
        self.before = {p: tree_snapshot(reg, CLASSES + "\\" + p) for p in PROTOCOLS}
        self.handlers = {p: effective_handler(p) for p in PROTOCOLS}
        # Never remove, rewrite or regenerate Windows' protected UserChoice.
        for protocol in PROTOCOLS:
            choice = (r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
                      + "\\" + protocol + r"\UserChoice")
            if tree_snapshot(reg, choice) is not None:
                raise ValueError("existing UserChoice prevents this bounded protocol pilot")

    def set_value(self, path, name, value, only_missing=False):
        reg = self.reg
        prefix = CLASSES
        for part in path[len(CLASSES) + 1:].split("\\"):
            prefix += "\\" + part
            try:
                reg.OpenKey(reg.HKEY_CURRENT_USER, prefix, 0, reg.KEY_READ).Close()
            except FileNotFoundError:
                reg.CreateKeyEx(reg.HKEY_CURRENT_USER, prefix, 0, reg.KEY_READ | reg.KEY_WRITE).Close()
                self.created.append(prefix)
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ | reg.KEY_WRITE) as key:
            try:
                old = reg.QueryValueEx(key, name)
            except FileNotFoundError:
                old = None
            if only_missing and old is not None:
                return
            self.values.append((path, name, old, (value, reg.REG_SZ)))
            reg.SetValueEx(key, name, 0, reg.REG_SZ, value)

    def apply(self, executable):
        for protocol in PROTOCOLS:
            root = CLASSES + "\\" + protocol
            command = root + r"\shell\open\command"
            snapshot = tree_snapshot(self.reg, command)
            if snapshot and any(n.casefold() == "delegateexecute" and value
                                for n, _, value in snapshot["values"]):
                raise ValueError("existing delegated protocol handler cannot be replaced by this pilot")
            if tree_snapshot(self.reg, root + r"\shell\open\ddeexec") is not None:
                raise ValueError("existing DDE protocol handler cannot be replaced by this pilot")
            self.set_value(root, "URL Protocol", "", only_missing=True)
            self.set_value(command, "", f'"{executable}" "%1"')
        notify_associations()
        for protocol in PROTOCOLS:
            handler = effective_handler(protocol)
            if not handler or not os.path.samefile(handler, executable):
                raise ValueError("effective protocol executable is not the exact owned capture; no dispatch allowed")

    def restore(self):
        reg = self.reg
        for path, name, old, written in reversed(self.values):
            with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ | reg.KEY_WRITE) as key:
                try:
                    current = reg.QueryValueEx(key, name)
                except FileNotFoundError:
                    current = None
                if current == old:
                    continue
                if current != written:
                    raise RuntimeError("protocol value changed outside the pilot; preserve evidence")
                if old is None:
                    reg.DeleteValue(key, name)
                else:
                    reg.SetValueEx(key, name, 0, old[1], old[0])
        for path in reversed(self.created):
            with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ) as key:
                subkeys, values, _ = reg.QueryInfoKey(key)
                if subkeys or values:
                    raise RuntimeError("new protocol key contains unexpected state; preserve evidence")
            reg.DeleteKey(reg.HKEY_CURRENT_USER, path)
        notify_associations()
        if {p: tree_snapshot(reg, CLASSES + "\\" + p) for p in PROTOCOLS} != self.before:
            raise RuntimeError("original protocol registry values were not restored")
        if {p: effective_handler(p) for p in PROTOCOLS} != self.handlers:
            raise RuntimeError("original effective protocol handlers were not restored")


def dispatch_owned_url(executable, url):
    class ExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG),
                    ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]
    shell, _ = shell_functions()
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    ole.CoUninitialize.argtypes = []
    ole.CoUninitialize.restype = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                               wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    info = ExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x100 | 0x400  # NOCLOSEPROCESS, NOASYNC, FLAG_NO_UI.
    info.lpVerb, info.lpFile, info.nShow = "open", url, 0
    if ole.CoInitializeEx(None, 0x2 | 0x4) not in (0, 1):
        raise OSError("controlled ShellExecuteExW COM initialization failed")
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
            raise OSError("controlled ShellExecuteExW did not return an exact process handle")
        image = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(image))
        if not kernel.QueryFullProcessImageNameW(info.hProcess, 0, image, ctypes.byref(size)):
            raise OSError("actual dispatched image observation unavailable")
        if not os.path.samefile(image.value, executable):
            raise RuntimeError("actual dispatched process is not the owned capture")
        pid = kernel.GetProcessId(info.hProcess)
        if pid <= 1 or kernel.WaitForSingleObject(info.hProcess, 3000) != 0:
            raise RuntimeError("exact owned protocol capture did not exit within its original bound")
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)) or code.value != 0:
            raise RuntimeError("owned protocol capture exited abnormally")
        return pid
    finally:
        if info.hProcess:
            kernel.CloseHandle(info.hProcess)
        ole.CoUninitialize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    require_scope(args.evidence_dir, os.environ)
    import winreg
    args.evidence_dir.mkdir(mode=0o700)
    capture = args.evidence_dir / "captured"
    capture.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location("pilot_artifacts", Path(__file__).with_name("prepare-test-examples.py"))
    artifacts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifacts)
    built = artifacts.build_artifacts([args.cargo, "+" + args.toolchain],
                                     ["--manifest-path", str(Path(__file__).resolve().parents[1] / "Cargo.toml"),
                                      "--example", "native_folder_opener", "--features", "engine-tests", "--offline"])
    source = built["native_folder_opener"]
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ValueError("exact regular Cargo artifact required")
    executable = args.evidence_dir / "owned protocol capture \u03b2.exe"
    shutil.copy2(source, executable)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if hashlib.sha256(executable.read_bytes()).hexdigest() != digest:
        raise ValueError("owned protocol capture copy differs")
    report = {"verysync_core_executed": False, "user_choice_modified": False,
              "per_machine_association_modified": False, "opener_sha256": digest,
              "actual_owned_dispatches": 0, "registry_restored": False}
    original_env = dict(os.environ)
    transaction = None
    try:
        # Exercise the actual restoration path after a controlled pre-dispatch
        # failure, then create a fresh transaction for the positive pilot.
        transaction = ProtocolTransaction(winreg)
        try:
            transaction.apply(executable)
            raise InterruptedError("intentional owned pre-dispatch pilot interruption")
        except InterruptedError:
            report["injected_pre_dispatch_failure_observed"] = True
        finally:
            completed = transaction
            transaction = None
            completed.restore()
            report["registry_restored"] = True
        report["injected_failure_registry_restored"] = True
        transaction = ProtocolTransaction(winreg)
        report["registry_restored"] = False
        transaction.apply(executable)
        os.environ["VERYSYNC_TEST_OPENER_CAPTURE_DIR"] = str(capture)
        for key in ("VERYSYNC_TEST_BROWSER_HOLD", "VERYSYNC_TEST_BROWSER_ACTOR", "VERYSYNC_TEST_OPENER_RUNTIME_PROBE"):
            os.environ.pop(key, None)
        for protocol in PROTOCOLS:
            url = f"{protocol}://127.0.0.1:1/owned-protocol-pilot/{secrets.token_hex(12)}"
            pid = dispatch_owned_url(executable, url)
            if (capture / f"{pid}.argv").read_bytes() != url.encode() + b"\0":
                raise RuntimeError("actual native protocol dispatch did not preserve the exact owned URL")
            report["actual_owned_dispatches"] += 1
        assert len(list(capture.glob("*.argv"))) == 2
    finally:
        os.environ.clear()
        os.environ.update(original_env)
        if transaction is not None:
            transaction.restore()
            report["registry_restored"] = True
        (args.evidence_dir / "observations.json").write_text(json.dumps(report), encoding="utf-8")
        print("Windows controlled protocol pilot: " + json.dumps(report), flush=True)
    executable.unlink()
    report["owned_executable_removed_after_exact_exit"] = not executable.exists()
    (args.evidence_dir / "observations.json").write_text(json.dumps(report), encoding="utf-8")
    print("Windows controlled protocol pilot complete: " + json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
