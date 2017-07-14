from . import SimLibrary
from .. import SIM_PROCEDURES as P
from ...calling_conventions import SimCCStdcall

lib = SimLibrary()
lib.set_library_names('kernel32.dll')
lib.add_all_from_dict(P['win32'])
lib.set_default_cc('X86', SimCCStdcall)
