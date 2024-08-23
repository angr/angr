from __future__ import annotations
from . import SimSyscallLibrary
from .. import SIM_PROCEDURES as P

lib = SimSyscallLibrary()
lib.set_library_names('cgcabi')
lib.add_all_from_dict(P['cgc'])
lib.add_number_mapping_from_dict('cgcabi', {
    1: '_terminate',
    2: 'transmit',
    3: 'receive',
    4: 'fdwait',
    5: 'allocate',
    6: 'deallocate',
    7: 'random',
})

lib_tracer = SimSyscallLibrary()
lib_tracer.set_library_names('cgcabi_tracer')
lib_tracer.add_all_from_dict(P['tracer'])
