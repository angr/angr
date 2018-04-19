from . import SimLibrary
from .. import SIM_PROCEDURES as P

libc = SimLibrary()
libc.set_library_names('libc.so.6', 'libc.so.0', 'libc.so')
libc.add_all_from_dict(P['libc'])
libc.add_all_from_dict(P['posix'])
libc.add_all_from_dict(P['glibc'])
libc.add_alias('abort', '__assert_fail', '__stack_chk_fail')
libc.add_alias('memcpy', 'memmove', 'bcopy')
libc.add_alias('getc', '_IO_getc')
libc.add_alias('putc', '_IO_putc')
libc.add_alias('read', 'recv')
libc.add_alias('write', 'send')
libc.set_non_returning('exit_group', 'exit', 'abort', 'pthread_exit', '__assert_fail',
    'longjmp', 'siglongjmp', '__longjmp_chk', '__siglongjmp_chk')
