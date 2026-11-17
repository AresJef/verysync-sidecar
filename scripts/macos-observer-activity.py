#!/usr/bin/env python3
"""Scoped diagnostic process activity; never alters native workers or power settings."""
import ctypes
import os
import sys
import threading

# Current Apple SDK Foundation/NSProcessInfo.h. Exclude both sleep inhibitors.
OPTIONS = 0xFF00000000 | (0x00FFFFFF & ~(1 << 20))
assert OPTIONS & ((1 << 20) | (1 << 40)) == 0
REASON = b"Bounded native resource observer diagnostic"


class NativeRuntime:
    """Exact Objective-C message signatures, with one owned autorelease pool."""
    def __init__(self):
        if sys.platform != "darwin":
            raise ValueError("process activity requires a native macOS observer")
        self.foundation = ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation")
        self.objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        self.objc.objc_getClass.argtypes = [ctypes.c_char_p]
        self.objc.objc_getClass.restype = ctypes.c_void_p
        self.objc.sel_registerName.argtypes = [ctypes.c_char_p]
        self.objc.sel_registerName.restype = ctypes.c_void_p
        address = ctypes.cast(self.objc.objc_msgSend, ctypes.c_void_p).value
        self.pointer = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(address)
        self.string = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(address)
        self.activity = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_uint64, ctypes.c_void_p)(address)
        self.void = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(address)
        self.void_argument = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(address)

    def selector(self, name):
        value = self.objc.sel_registerName(name)
        if not value:
            raise RuntimeError("native activity selector unavailable")
        return value

    def start(self, options):
        pool_class = self.objc.objc_getClass(b"NSAutoreleasePool")
        process_class = self.objc.objc_getClass(b"NSProcessInfo")
        string_class = self.objc.objc_getClass(b"NSString")
        if not all((pool_class, process_class, string_class)):
            raise RuntimeError("native activity classes unavailable")
        pool = self.pointer(pool_class, self.selector(b"new"))
        if not pool:
            raise RuntimeError("native activity autorelease pool unavailable")
        try:
            process = self.pointer(process_class, self.selector(b"processInfo"))
            reason = self.string(string_class, self.selector(b"stringWithUTF8String:"), REASON)
            if not process or not reason:
                raise RuntimeError("native process activity arguments unavailable")
            token = self.activity(process, self.selector(b"beginActivityWithOptions:reason:"), options, reason)
            if not token:
                raise RuntimeError("native activity token unavailable")
            return pool, process, token
        except BaseException:
            self.void(pool, self.selector(b"drain"))
            raise

    def end(self, handle):
        pool, process, token = handle
        try:
            self.void_argument(process, self.selector(b"endActivity:"), token)
        finally:
            self.void(pool, self.selector(b"drain"))


class ObserverActivity:
    """Explicitly bracket only the observer process after native worker startup."""
    def __init__(self, runtime=None):
        self.runtime = runtime
        self.handle = None
        self.owner = None
        self.started = False
        self.ended = False

    def begin(self, *, worker_started):
        if not worker_started or self.started:
            raise ValueError("activity must begin once after the native workers exist")
        if self.runtime is None:
            self.runtime = NativeRuntime()
        self.owner = (os.getpid(), threading.get_ident())
        self.handle = self.runtime.start(OPTIONS)
        self.started = True
        return self.report()

    def close(self):
        if not self.started or self.ended:
            return
        if self.owner != (os.getpid(), threading.get_ident()):
            raise RuntimeError("only the creating observer thread may end this activity")
        self.runtime.end(self.handle)
        self.handle = None
        self.ended = True

    def report(self):
        return {"scope": "observer-process-only", "worker_started_before_begin": self.started,
                "requested_options": OPTIONS, "started": self.started, "ended": self.ended,
                "idle_sleep_disabled": False, "display_sleep_disabled": False,
                "system_settings_changed": False, "diagnostic_only": True,
                "timer_improvement_or_frozen_membership_claimed": False}
