from z3 import *
import symmemory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

expr = (2*x + 1)
mm = symmemory.MemoryMap()
print 'Range: ', mm.get_index_scope(expr, x)
