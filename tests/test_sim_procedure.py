import angr
import claripy
import nose

def test_ret_float():
    p = angr.load_shellcode(b'X', arch='i386')

    class F1(angr.SimProcedure):
        def run(self):
            return 12.5

    p.hook(0x1000, F1(cc=p.factory.cc(func_ty=angr.sim_type.parse_file('float (x)();')[0]['x'])))
    p.hook(0x2000, F1(cc=p.factory.cc(func_ty=angr.sim_type.parse_file('double (x)();')[0]['x'])))

    s = p.factory.call_state(addr=0x1000, ret_addr=0)
    succ = s.step()
    nose.tools.assert_equal(len(succ.successors), 1)
    s2 = succ.flat_successors[0]
    nose.tools.assert_false(s2.regs.st0.symbolic)
    nose.tools.assert_equal(s2.solver.eval(s2.regs.st0.get_bytes(4, 4).raw_to_fp()), 12.5)

    s = p.factory.call_state(addr=0x2000, ret_addr=0)
    succ = s.step()
    nose.tools.assert_equal(len(succ.successors), 1)
    s2 = succ.flat_successors[0]
    nose.tools.assert_false(s2.regs.st0.symbolic)
    nose.tools.assert_equal(s2.solver.eval(s2.regs.st0.raw_to_fp()), 12.5)

if __name__ == '__main__':
    test_ret_float()
