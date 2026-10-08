"""
Manage OS-level configuration.
"""

from __future__ import annotations

from collections import defaultdict

from elftools.elf.descriptions import _DESCR_EI_OSABI

from .cgc import SimCGC
from .freebsd import SimFreeBSD
from .javavm import SimJavaVM
from .linux import SimLinux
from .simos import SimOS
from .snimmuc_nxp import SimSnimmucNxp
from .uefi import SimUefi
from .userland import SimUserland
from .windows import SimWindows
from .xbox import SimXbox

os_mapping = defaultdict(lambda: SimOS)


def register_simos(name, cls):
    os_mapping[name] = cls


# Pulling in all EI_OSABI options supported by elftools
for v in _DESCR_EI_OSABI.values():
    register_simos(v, SimLinux)

# ... except the ones angr models in their own right. This has to follow the loop above,
# which claims every EI_OSABI value for Linux.
register_simos(_DESCR_EI_OSABI["ELFOSABI_FREEBSD"], SimFreeBSD)

register_simos("linux", SimLinux)
register_simos("windows", SimWindows)
register_simos("cgc", SimCGC)
register_simos("javavm", SimJavaVM)
register_simos("snimmuc_nxp", SimSnimmucNxp)
register_simos("uefi", SimUefi)
register_simos("xbox", SimXbox)


__all__ = (
    "SimCGC",
    "SimFreeBSD",
    "SimJavaVM",
    "SimLinux",
    "SimOS",
    "SimSnimmucNxp",
    "SimUefi",
    "SimUserland",
    "SimWindows",
    "os_mapping",
)
