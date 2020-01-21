import angr
import glob
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_stack_end():
    for fn in glob.glob(os.path.join(test_location, "*", "fauxware")):
        p = angr.Project(fn, auto_load_libs=False)

        # normal state
        s = p.factory.full_init_state()
        offset = s.solver.eval(p.arch.initial_sp - s.regs.sp)

        # different stack ends
        for n in [ 0x1337000, 0xbaaaaa00, 0x100, 0xffffff00, 0x13371337000, 0xbaaaaaaa0000, 0xffffffffffffff00 ]:
            if n.bit_length() > p.arch.bits:
                continue
            s = p.factory.full_init_state(stack_end=n)
            assert s.solver.eval_one(s.regs.sp + offset == n)

def test_brk():
    for fn in glob.glob(os.path.join(test_location, "*", "fauxware")):
        p = angr.Project(fn, auto_load_libs=False)

        # different stack ends
        for n in [ 0x1337000, 0xbaaaaa00, 0x100, 0xffffff00, 0x13371337000, 0xbaaaaaaa0000, 0xffffffffffffff00 ]:
            if n.bit_length() > p.arch.bits:
                continue
            s = p.factory.full_init_state(brk=n)
            assert s.solver.eval_one(s.posix.brk == n)

if __name__ == '__main__':
    test_stack_end()
    test_brk()
