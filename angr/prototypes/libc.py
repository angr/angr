
from .sim_prototypes import SimPrototypes

libc = SimPrototypes(
    'libc',
    alternative_names=['libc.so.6'],
)

libc.add_c_proto('int strcmp (const char * str1, const char * str2);')
libc.add_c_proto('int puts (const char * str);')
