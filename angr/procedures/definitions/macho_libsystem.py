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

# Mach-O naming convention adds an underscore prefix to function names
for name, _ in P["libc"].items():
    libc.add_alias(name, "_" + name)
