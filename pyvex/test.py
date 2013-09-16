import pyvex

irsb = pyvex.IRSB(bytes='\x55\xc3')

print "PPrinting irsb %s" % irsb
irsb.pp()

for stmt in irsb.statements():
	print "PPrinting statment at %s" % (stmt)
	stmt.pp()
	print
	print "====================="

print "PPrinting deepCopy of first statement"
stmt.deepCopy().pp()
print

print irsb

print "MADE IT TO THE END WITHOUT SEGFAULT"
