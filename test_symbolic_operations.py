from z3 import *
import symbolic_operations

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

print "Testing range function"
expr = 2*x + 1
r = symbolic_operations.get_max_min(expr)
print r
if r[0] == 1 and r[1] == 18446744073709551615:
    print 'OK'
else:
    print 'FAIL'
