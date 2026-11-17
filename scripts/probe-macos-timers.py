#!/usr/bin/env python3
"""Bounded observer-only clock diagnosis; no engine or resource acceptance."""
import argparse
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import select
import platform
import sys
import time


class CriticalKqueueTicker:
    """One owned periodic timer, with the Apple SDK's minimum-coalescing flag."""
    def __init__(self):
        self.queue = select.kqueue()
        self.expirations = None
        # sys/event.h: NOTE_NSECONDS=4, NOTE_CRITICAL=32. CPython does not
        # expose these macOS flags. This is interval mode, not an epoch guess.
        self.parameters = {"interval_ns": 10_000_000, "fflags": 4 | 32}
        try:
            self.queue.control([select.kevent(1, filter=select.KQ_FILTER_TIMER,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE,
                fflags=self.parameters["fflags"], data=10_000_000)], 0, 0)
        except BaseException:
            self.queue.close()
            raise

    def wait(self):
        events = self.queue.control(None, 1, 2)
        if len(events) != 1:
            raise RuntimeError("owned critical timer did not return one event within 2s")
        event = events[0]
        if (event.ident != 1 or event.filter != select.KQ_FILTER_TIMER
                or event.flags & select.KQ_EV_ERROR or event.data < 1):
            raise RuntimeError("owned critical timer returned an invalid event")
        self.expirations = event.data

    def close(self):
        self.queue.close()


def probe(output):
    if sys.platform != "darwin":
        raise ValueError("explicit macOS observer process required")
    spec = importlib.util.spec_from_file_location("frozen_sampler",
        Path(__file__).with_name("measure-native-resources.py"))
    sampler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sampler)
    report = {"role": "observer-only clock diagnosis; no native worker or resource result",
              "formal_sample": False, "python": sys.version,
              "platform": platform.platform(),
              "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "sampler_sha256": hashlib.sha256(
                  Path(__file__).with_name("measure-native-resources.py").read_bytes()).hexdigest(),
              "clock": vars(time.get_clock_info("perf_counter")),
              "thread_cpu_clock": vars(time.get_clock_info("thread_time")),
              "qos": sampler.observer_thread_policy(), "blocks": []}
    started = time.monotonic()
    gc_start = {}
    gc_events = []

    def on_gc(phase, info):
        generation = info["generation"]
        if phase == "start":
            gc_start[generation] = time.perf_counter_ns()
        elif generation in gc_start:
            gc_events.append({"generation": generation,
                              "elapsed_ns": time.perf_counter_ns() - gc_start.pop(generation)})

    gc.callbacks.append(on_gc)
    try:
        # Complete ABBA clock blocks, retaining every slow and fast wait.
        for name in ["mach", "critical-kqueue", "critical-kqueue", "mach"]:
            ticker = sampler.SamplerTicker(10) if name == "mach" else CriticalKqueueTicker()
            block = {"timer": name, "parameters": ticker.parameters, "rows": []}
            report["blocks"].append(block)
            previous = time.perf_counter_ns()
            try:
                for _ in range(64):
                    if time.monotonic() - started > 20:
                        raise TimeoutError("original 20s clock-probe bound reached")
                    cpu_before = time.thread_time_ns()
                    before = time.perf_counter_ns()
                    ticker.wait()
                    after = time.perf_counter_ns()
                    cpu_after = time.thread_time_ns()
                    block["rows"].append({"gap_ns": after-previous, "wait_ns": after-before,
                        "cpu_window_ns": cpu_after-cpu_before, "expirations": ticker.expirations})
                    previous = after
            finally:
                ticker.close()
            block["max_gap_ns"] = max(row["gap_ns"] for row in block["rows"])
            block["gaps_over_existing_50ms_limit"] = sum(
                row["gap_ns"] > 50_000_000 for row in block["rows"])
        report["status"] = "COMPLETE_CLOCK_DIAGNOSIS_ONLY"
    except BaseException as error:
        report.update(status="ERROR", error_type=type(error).__name__)
        raise
    finally:
        gc.callbacks.remove(on_gc)
        report.update(gc_events=gc_events, elapsed_s=time.monotonic()-started)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "formal_sample": False,
        "blocks": [{k: v for k, v in block.items() if k != "rows"} for block in report["blocks"]]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    probe(parser.parse_args().output)
