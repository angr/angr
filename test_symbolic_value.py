from z3 import *
import pysex.s_value

x = BitVec('x', 64)
j = BitVec('j', 64)
z = BitVec('z', 64)

print "Testing range function"
expr = 2*x + 1
v = pysex.s_value.Value(expr)
r = ( v.min, v.max )
if r[0] == 1 and r[1] == 18446744073709551615:
    print 'OK'
else:
    print 'FAIL'
