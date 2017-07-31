from . import SimSyscallLibrary
from .. import SIM_PROCEDURES as P

lib = SimSyscallLibrary()
lib.set_library_names('cgcabi')
lib.add_all_from_dict(P['cgc'])
lib.add_number_mapping_from_dict('X86', {
    1: '_terminate',
    2: 'transmit',
    3: 'receive',
    4: 'fdwait',
    5: 'allocate',
    6: 'deallocate',
    7: 'random',
})
