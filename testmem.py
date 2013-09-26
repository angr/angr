from z3 import *
import symbolic_memory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

expr = 2*x + 1
mm = symbolic_memory.MemoryMap()
r = mm.get_index_scope(expr)
s = Solver()
s.add(expr == mm._h_value)
s.add(x >= 0)
print 'Range: ', r
mm.store(0xFF, 5)
mm.load(0xFE)
mm.load(0xFF)
