from z3 import *
import symbolic_memory

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

print "Testing range function"
expr = 2*x + 1
mm = symbolic_memory.MemoryMap()
r = mm.get_index_scope(expr)
if r[0] == 1 and r[1] == 18446744073709551615:
    print 'OK'
else:
    print 'FAIL'

print "Testing store and load functions"
bit = z3.BitVec("Var_2_bytes", 16)
mm.store(0x00, bit, 2)
mm.load(0, 2)
mm.load(2, 1)
