"""Fixed operation names for the owned native acceptance fixtures."""
from types import MappingProxyType

SCHEDULES = MappingProxyType({
    f"schedule-{trigger}-{step}": (trigger, step)
    for trigger in ("watch", "interval", "calendar")
    for step in ("prepare", "seed", "observe", "finish")
})
SCHEDULE_MODIFICATIONS = frozenset(
    operation for operation, (_, step) in SCHEDULES.items() if step != "observe"
)


AUDIT = MappingProxyType({
    f"audit-{step}": step
    for step in ("prepare", "record", "observe", "reset", "finish")
})
AUDIT_MODIFICATIONS = frozenset(operation for operation, step in AUDIT.items() if step != "observe")
SELECTIVE = MappingProxyType({
    f"selection-{step}": step
    for step in ("prepare", "select-file", "deselect-file", "select-directory", "select-root", "remove-from-all", "finish")
})
TWO_CORE_SCOPES = MappingProxyType({
    "audit": AUDIT,
    "selective": SELECTIVE,
    "pro-cases": MappingProxyType({**SCHEDULES, **SELECTIVE, **AUDIT}),
})

def two_core_request(scope, operation, request_id):
    step = TWO_CORE_SCOPES[scope][operation]
    if operation in SCHEDULES:
        trigger, action = step
        return {"kind":"schedule","trigger":trigger,"step":action,"request":request_id}
    kind = "audit" if operation in AUDIT else "selective"
    return {"kind":kind,"step":step,"request":request_id}
