"""Validate the temporary process group used by the current-login handoff."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat


TMP = Path("/private/tmp")
VAULT = re.compile(r"r33-session-[a-z0-9_]{8}\Z")
GROUP_FORMAT = "r33-isolation-current-login-v1"


@dataclass(frozen=True)
class GroupBoundary:
    private: Path
    group: int

    @classmethod
    def current(cls, private):
        private = Path(private)
        root = private.parent
        if (root.parent != TMP or not VAULT.fullmatch(root.name) or private.name != "owner"
                or private.resolve() != private):
            raise ValueError("Use the temporary permissions created for this local handoff.")
        guard, own = root.lstat(), private.lstat()
        group = os.getegid()
        if (os.getuid() in {0, group} or group < 280000
                or not stat.S_ISDIR(guard.st_mode) or stat.S_IMODE(guard.st_mode) != 0o710
                or guard.st_uid != 0 or guard.st_gid != group
                or not stat.S_ISDIR(own.st_mode) or own.st_uid != os.getuid()
                or own.st_gid != group or stat.S_IMODE(own.st_mode) != 0o700):
            raise ValueError("The kernel did not establish private access for this run.")
        return cls(private, group)

    def owns_terminal(self, attributes):
        return all(item.st_uid == 0 and item.st_gid == self.group
                   and stat.S_IMODE(item.st_mode) == 0o600 for item in attributes)
