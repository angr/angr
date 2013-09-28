import z3
import symbolic_ccall

def main():
    print "Testing amd64_actions_ADD"
    print "(8-bit) 1 + 1...",
    arg_l = z3.BitVecVal(1, 8)
    arg_r = z3.BitVecVal(1, 8)
    ret = symbolic_ccall.amd64_actions_ADD(8, arg_l, arg_r, 0)
    if ret == 0:
        print "PASS"
    else:
        print "FAILED"

    print "(32-bit) (-1) + (-2)...",
    arg_l = z3.BitVecVal(-1, 32)
    arg_r = z3.BitVecVal(-1, 32)
    ret = symbolic_ccall.amd64_actions_ADD(32, arg_l, arg_r, 0)
    if ret == 0b101010:
        print "PASS"
    else:
        print "FAILED"

    print "Testing amd64_actions_SUB"
    print "(8-bit) 1 - 1...",
    arg_l = z3.BitVecVal(1, 8)
    arg_r = z3.BitVecVal(1, 8)
    ret = symbolic_ccall.amd64_actions_SUB(8, arg_l, arg_r, 0)
    if ret == 0b010100:
        print "PASS"
    else:
        print "FAILED"

    print "(32-bit) (-1) - (-2)...",
    arg_l = z3.BitVecVal(-1, 32)
    arg_r = z3.BitVecVal(-1, 32)
    ret = symbolic_ccall.amd64_actions_SUB(32, arg_l, arg_r, 0)
    if ret == 0:
        print "PASS"
    else:
        print "FAILED"


if __name__ == "__main__":
    main()
