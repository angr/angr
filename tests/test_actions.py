import simuvex
from simuvex import SimState, SimProcedures
import nose

def test_procedure_actions():
    s = SimState()

    s.registers.store('rbx', 2)
    rbx = SimProcedures['testing']['retreg'](s, addr=0x10, arguments=(), sim_kwargs={'reg': 'rbx'}).ret_expr
    nose.tools.assert_is(type(rbx), simuvex.SimActionObject)
    nose.tools.assert_equal(s.se.any_int(rbx), 2)
    nose.tools.assert_equal(rbx.reg_deps, { s.arch.registers['rbx'][0] })

if __name__ == '__main__':
    test_procedure_actions()
