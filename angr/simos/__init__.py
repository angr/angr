"""
Manage OS-level configuration.
"""

from collections import defaultdict
from elftools.elf.descriptions import _DESCR_EI_OSABI

from .simos import SimOS
from .userland import SimUserland
from .linux import SimLinux
from .cgc import SimCGC
from .windows import SimWindows
from .javavm import SimJavaVM
from .snimmuc_nxp import SimSnimmucNxp

os_mapping = defaultdict(lambda: SimOS)


def register_simos(name, cls):
    os_mapping[name] = cls


# Pulling in all EI_OSABI options supported by elftools
for k, v in _DESCR_EI_OSABI.items():
    register_simos(v, SimLinux)

register_simos("linux", SimLinux)
register_simos("windows", SimWindows)
register_simos("cgc", SimCGC)
register_simos("javavm", SimJavaVM)
register_simos("snimmuc_nxp", SimSnimmucNxp)
