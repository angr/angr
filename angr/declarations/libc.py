
from .sim_declarations import SimDeclarations

libc = SimDeclarations('libc')

libc.add_c_decl('int strcmp (const char * str1, const char * str2);')
