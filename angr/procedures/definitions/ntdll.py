from . import SimLibrary
from .. import SIM_PROCEDURES as P
from ...calling_conventions import SimCCStdcall

lib = SimLibrary()
lib.set_library_names('ntdll.dll')
lib.add_all_from_dict(P['ntdll'])
lib.set_default_cc('X86', SimCCStdcall)

lib.add('RtlEncodePointer', P['win32']['EncodePointer'])
lib.add('RtlDecodePointer', P['win32']['EncodePointer'])
lib.add('RtlAllocateHeap', P['win32']['HeapAlloc'])
