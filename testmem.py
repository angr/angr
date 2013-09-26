from z3 import *
import symbolic_memory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

expr = 2*x + 1
mm = symbolic_memory.MemoryMap()
print 'Range: ', mm.get_index_scope(expr, x)
