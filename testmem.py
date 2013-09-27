from z3 import *
import symbolic_memory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

expr = 2*x + 1
mm = symbolic_memory.MemoryMap()
# r = mm.get_index_scope(expr)
# print 'Range: ', r
bit = z3.BitVec("Var_2_bytes", 16)
mm.store(0x00, bit, 2)
a = mm.load(0)
a = mm.load(8)
