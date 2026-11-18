"""Read atomic Darwin counters for already admitted test processes."""
import ctypes
import time


class Sample(ctypes.Structure):
    _fields_ = [
        ("birth_us", ctypes.c_uint64),
        ("rss_bytes", ctypes.c_uint64),
        ("user_ns", ctypes.c_uint64),
        ("system_ns", ctypes.c_uint64),
    ]

    def counters(self):
        return {"rss_bytes": self.rss_bytes, "cpu_user_s": self.user_ns / 1_000_000_000,
                "cpu_system_s": self.system_ns / 1_000_000_000}


def require_counter_agreement(before, sample, after):
    if not min(before["rss_bytes"], after["rss_bytes"]) <= sample["rss_bytes"] <= max(before["rss_bytes"], after["rss_bytes"]):
        raise RuntimeError("native RSS differs from reference bounds")
    for key in ("cpu_user_s", "cpu_system_s"):
        first, actual, last = (round(read[key] * 1_000_000_000) for read in (before, sample, after))
        if not first - 1_000 <= actual <= last + 1_000:
            raise RuntimeError("native CPU counter differs from reference bounds")


class OwnedReader:
    def __init__(self, library):
        self.library = ctypes.CDLL(str(library))
        prepare = self.library.prepare_owned_reader
        prepare.argtypes = []
        prepare.restype = ctypes.c_int
        if prepare() != 0:
            raise RuntimeError("native timebase initialization failed")
        self.read = self.library.read_owned_sample
        self.read.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(Sample)]
        self.read.restype = ctypes.c_int

    def bind(self, process, parent, reference):
        before = reference(process)
        sample = Sample()
        pointer = ctypes.byref(sample)
        if self.read(process.pid, parent, 0, pointer) != 0:
            raise RuntimeError("initial native ownership binding failed")
        after = reference(process)
        birth = sample.birth_us
        creation = before["creation_time"]
        if abs(birth - round(creation * 1_000_000)) > 1 or creation != after["creation_time"]:
            raise RuntimeError("native birth identity differs from the reference")
        require_counter_agreement(before, sample.counters(), after)
        if self.read(process.pid, parent + 1, birth, pointer) != 1:
            raise RuntimeError("native reader accepted the wrong parent")
        if self.read(process.pid, parent, birth + 1, pointer) != 2:
            raise RuntimeError("native reader accepted the wrong birth identity")
        return parent, birth, creation, sample, pointer

    def snapshot(self, process, binding):
        start = time.perf_counter_ns()
        parent, birth, creation, sample, pointer = binding
        if self.read(process.pid, parent, birth, pointer) != 0:
            raise RuntimeError("native identity ended, changed or could not be read")
        return {"pid": process.pid, "creation_time": creation, **sample.counters(),
                "read_start_ns": start, "read_end_ns": time.perf_counter_ns()}
