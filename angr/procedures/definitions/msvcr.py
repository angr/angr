# Microsoft Visual C/C++ Runtime
from __future__ import annotations

from angr.calling_conventions import SimCCMicrosoftAMD64
from angr.procedures.procedure_dict import SIM_PROCEDURES as P

from . import SimLibrary

libc = SimLibrary()
libc.set_library_names(
    "msvcrt.dll",
    "msvcr71.dll",
    "msvcr80.dll",
    "msvcr90.dll",
    "msvcr100.dll",
    "msvcr110.dll",
    "msvcrt20.dll",
    "msvcrt40.dll",
    "msvcr120.dll",
)
libc.add_all_from_dict(P["libc"])
libc.add_all_from_dict(P["msvcr"])  # overwrite any that are also defined in libc
libc.set_non_returning("_exit", "abort", "exit", "_invoke_watson")

libc.add_alias("_initterm", "_initterm_e")

libc.set_default_cc("AMD64", SimCCMicrosoftAMD64)

def publish_procedure_prototypes() -> None:
    """
    Publish each SimProcedure's own prototype as the library prototype, so that callers of msvcrt
    functions get argument and return atoms even without a header-derived signature.

    The VM deobfuscator calls this because its Windows targets reach msvcrt through imports it has
    no declarations for. It is deliberately not done at import time: library prototypes are
    process-global, and changing them changes what every other analysis infers about these
    functions.
    """
    for name, procedure in libc.procedures.items():
        if procedure.prototype is not None:
            libc.set_prototype(name, procedure.prototype)
