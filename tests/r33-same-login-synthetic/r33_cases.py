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


def schedule_request(operation, request_id):
    trigger, step = SCHEDULES[operation]
    return {"kind": "schedule", "trigger": trigger, "step": step, "request": request_id}
