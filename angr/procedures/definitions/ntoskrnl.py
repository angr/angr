from . import SimLibrary
from .. import SIM_PROCEDURES as P
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64

lib = SimLibrary()
lib.set_library_names("ntoskrnl.exe")
lib.add_all_from_dict(P["win32_kernel"])
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
