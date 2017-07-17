
from .sim_declarations import SimDeclarations

libc = SimDeclarations(
    'libc',
    alternative_names=['libc.so.6'],
)

libc.add_c_decl('int strcmp (const char * str1, const char * str2);')
