from z3 import *
import memorymap

x = Int('x')
j = Int('j')
z = Int('z')

expr = Int('expr')
expr = (2*x + x + 1 + j) + 50*z
mm = memorymap.MemoryMap()
print 'Range: ', mm.get_index_scope(expr, [x,j,z])
