"""Exercise supervisor routing with local fixture bytes and a synthetic login."""

import hashlib
from pathlib import Path

from r33_cases import AUDIT, SCHEDULES, SELECTIVE
from r33_protocol import DENIED


class SimulatedCases:
    def __init__(self, root):
        self.root = root
        self.case = None
        self.effects = []
        self.refresh = 0

    def run_case(self, operation):
        if operation in SCHEDULES:
            trigger, step = SCHEDULES[operation]
            name, case = "schedule-" + trigger, ["prepare", "seed", "observe", "finish"]
        elif operation in SELECTIVE:
            name, step = "selection", SELECTIVE[operation]
            case = ["prepare", "select-file", "deselect-file", "select-directory",
                    "select-root", "remove-from-all", "finish"]
        elif operation in AUDIT:
            name, step = "audit", AUDIT[operation]
            case = ["prepare", "record", "observe", "reset", "finish"]
        else:
            return DENIED
        if self.case is None:
            if step != "prepare":
                return DENIED
            self.case = (name, 0)
        if self.case[0] != name or case[self.case[1]] != step:
            return DENIED
        sample = self.root / ("case-" + name)
        expected = (self.root.name + "/" + name).encode()
        evidence = {"ok": True, "fixture": name, "action": step, "synthetic": True}
        if step == "seed" or step == "record" or step == "select-file":
            with sample.open("xb") as output:
                output.write(expected)
        elif step == "observe" or step == "select-root":
            data = sample.read_bytes()
            if data != expected:
                return DENIED
            evidence.update({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        elif step == "finish":
            self.effects.append(name)
            sample.unlink()
            evidence["owned_sample_removed"] = not sample.exists()
        if step == "finish":
            self.case = None
        else:
            self.case = (name, self.case[1] + 1)
        return evidence

    def paid_refresh(self):
        if self.refresh:
            return DENIED
        self.refresh += 1
        return {"ok": True, "synthetic": True, "refresh_count": self.refresh}

    def finish(self):
        for file in self.root.glob("case-*"):
            if file.is_file():
                file.unlink()

