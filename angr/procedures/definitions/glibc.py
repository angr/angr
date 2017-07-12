from . import SimLibrary
from .. import SIM_PROCEDURES as P

libc = SimLibrary()
libc.set_names('libc.so.6', 'libc.so.0', 'libc.so')
libc.add_all_from_dict(P['libc'])
libc.add_all_from_dict(P['posix'])
libc.add_all_from_dict(P['glibc'])
libc.alias('abort', '__assert_fail', '__stack_chk_fail')
libc.alias('memcpy', 'memmove', 'bcopy')
