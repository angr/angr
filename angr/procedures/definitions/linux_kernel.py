from . import SimSyscallLibrary
from .. import SIM_PROCEDURES as P

lib = SimSyscallLibrary()
lib.set_library_names('linux')
lib.add_all_from_dict(P['linux_kernel'])
lib.add_alias('exit', 'exit_group')

lib.add_number_mapping_from_dict('AMD64', {
    0:   'read',
    1:   'write',
    2:   'open',
    3:   'close',
    4:   'stat',
    5:   'fstat',
    6:   'stat',
    8:   'lseek',
    9:   'mmap',
    10:  'mprotect',
    11:  'munmap',
    12:  'brk',
    13:  'sigaction',
    14:  'sigprocmask',
    39:  'getpid',
    60:  'exit',
    63:  'uname',
    87:  'unlink',
    97:  'getrlimit',
    158: 'arch_prctl',
    186: 'gettid',
    201: 'time',
    202: 'futex',
    218: 'set_tid_address',
    231: 'exit_group',
    234: 'tgkill',
})

lib.add_number_mapping_from_dict('X86', {
    1:   'exit',
    3:   'read',
    4:   'write',
    5:   'open',
    6:   'close',
    13:  'time',
    45:  'brk',
    122: 'uname',
    252: 'exit_group',
})

lib.add_number_mapping_from_dict('PPC32', {
    1:  'exit',
    3:  'read',
    4:  'write',
    5:  'open',
    6:  'close',
    45: 'brk',
})

lib.add_number_mapping_from_dict('MIPS32', {
    4001: 'exit',
    4003: 'read',
    4004: 'write',
    4005: 'open',
    4006: 'close',
    4045: 'brk',
})

lib.add_number_mapping_from_dict('MIPS64', {
    5000: 'read',
    5001: 'write',
    5002: 'open',
    5003: 'close',
    5012: 'brk',
    5058: 'exit',
})
