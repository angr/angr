
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

os_mapping = defaultdict(lambda: SimOS)


def register_simos(name, cls):
    os_mapping[name] = cls


# Pulling in all EI_OSABI options supported by elftools
for k, v in _DESCR_EI_OSABI.items():
    register_simos(v, SimLinux)

register_simos('windows', SimWindows)
register_simos('cgc', SimCGC)
