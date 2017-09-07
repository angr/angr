from . import SimLibrary
from .. import SIM_PROCEDURES as P
from ...calling_conventions import SimCCStdcall, SimCCCdecl

lib = SimLibrary()
lib.set_library_names('user32.dll')
lib.add_all_from_dict(P['win_user32'])
lib.set_default_cc('X86', SimCCStdcall)

import archinfo
lib.add('wsprintfA', P['libc']['sprintf'], cc=SimCCCdecl(archinfo.ArchX86()))
