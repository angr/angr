import angr
import z3

b = angr.Binary("/home/yans/code/v/test.o")
f = b.functions[0]
v = f.vex_blocks()

print "Got %d blocks!" % len(v)
