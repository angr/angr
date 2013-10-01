import os
import z3
import pysex.s_ccall

def main():
	# init z3
	z3_path = os.environ.get('Z3PATH')
	if z3_path == None:
		z3_path = "/opt/python/lib/"
	try:
		z3.init(z3_path + "libz3.so")
	except:
		print "z3 initialization failed. Please set $Z3PATH accordingly."
		return

	print "Testing amd64_actions_ADD"
	print "(8-bit) 1 + 1...",
	arg_l = z3.BitVecVal(1, 8)
	arg_r = z3.BitVecVal(1, 8)
	ret = pysex.s_ccall.amd64_actions_ADD(8, arg_l, arg_r, 0)
	if ret == 0:
	    print "PASS"
	else:
	    print "FAILED"

	print "(32-bit) (-1) + (-2)...",
	arg_l = z3.BitVecVal(-1, 32)
	arg_r = z3.BitVecVal(-1, 32)
	ret = pysex.s_ccall.amd64_actions_ADD(32, arg_l, arg_r, 0)
	if ret == 0b101010:
	    print "PASS"
	else:
	    print "FAILED"

	print "Testing amd64_actions_SUB"
	print "(8-bit) 1 - 1...",
	arg_l = z3.BitVecVal(1, 8)
	arg_r = z3.BitVecVal(1, 8)
	ret = pysex.s_ccall.amd64_actions_SUB(8, arg_l, arg_r, 0)
	if ret == 0b010100:
	    print "PASS"
	else:
	    print "FAILED"

	print "(32-bit) (-1) - (-2)...",
	arg_l = z3.BitVecVal(-1, 32)
	arg_r = z3.BitVecVal(-1, 32)
	ret = pysex.s_ccall.amd64_actions_SUB(32, arg_l, arg_r, 0)
	if ret == 0:
	    print "PASS"
	else:
	    print "FAILED"


if __name__ == "__main__":
	main()
