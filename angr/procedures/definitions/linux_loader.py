from __future__ import annotations
from . import SimLibrary
from .. import SIM_PROCEDURES as P

lib = SimLibrary()
lib.set_library_names('ld.so', 'ld-linux.so', 'ld.so.2', 'ld-linux.so.2', 'ld-linux-x86-64.so.2')
lib.add_all_from_dict(P['linux_loader'])
