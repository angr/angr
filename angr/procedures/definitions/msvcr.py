# Microsoft Visual C/C++ Runtime
from . import SimLibrary
from .. import SIM_PROCEDURES as P
from ...calling_conventions import SimCCMicrosoftAMD64

libc = SimLibrary()
libc.set_library_names('msvcrt.dll', 'msvcr71.dll', 'msvcr100.dll', 'msvcr110.dll', 'msvcrt20.dll', 'msvcrt40.dll',
                       'msvcr120.dll')
libc.add_all_from_dict(P['libc'])
libc.add_all_from_dict(P['msvcr']) # overwrite any that are also defined in libc
libc.set_non_returning('_exit', 'abort', 'exit', '_invoke_watson')

libc.add_alias('_initterm', '_initterm_e')

libc.set_default_cc('AMD64', SimCCMicrosoftAMD64)
