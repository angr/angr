import pyvex

irsb = pyvex.IRSB(bytes='\x55\xc3')

for stmt in irsb.statements():
	print "Showing statment at %s" % (stmt)
	stmt.pp()
	print
	print "====================="
