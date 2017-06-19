import simuvex
from simuvex import SimState, SimProcedures, SimEngineProcedure
import nose

FAKE_ADDR = 0x100000

def test_procedure_actions():
    s = SimState()

    s.registers.store('rbx', 2)
    proc = SimProcedures['testing']['retreg'](FAKE_ADDR, s.arch, sim_kwargs={'reg': 'rbx'})
    SimEngineProcedure().process(s, proc)
    rbx = proc.ret_expr
    nose.tools.assert_is(type(rbx), simuvex.SimActionObject)
    nose.tools.assert_equal(s.se.any_int(rbx), 2)
    nose.tools.assert_equal(rbx.reg_deps, { s.arch.registers['rbx'][0] })

if __name__ == '__main__':
    test_procedure_actions()
