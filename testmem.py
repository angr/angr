from z3 import *
import symbolic_memory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

expr = x
mm = symbolic_memory.MemoryMap()
print 'Range: ', mm.get_index_scope(expr)
mm.store(0xFF, 5)
mm.load(0xFE)
mm.load(0xFF)
