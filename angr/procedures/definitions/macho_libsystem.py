from __future__ import annotations
from angr.procedures import SIM_PROCEDURES as P
from . import SimLibrary

libc = SimLibrary()
libc.set_library_names(
    "libSystem.dylib",
    "libSystem.B.dylib",
)
# TODO: add more functions
libc.add_all_from_dict(P["libc"])
libc.add_all_from_dict(P["posix"])

libc.add_alias("abort", "__stack_chk_fail")

# Mach-O naming convention adds an underscore prefix to function names
for name in list(libc.procedures):
    libc.add_alias(name, "_" + name)
