import angr
from angr import SimState, SIM_PROCEDURES
from angr.engines import SimEngineProcedure
import nose

FAKE_ADDR = 0x100000

def test_procedure_actions():
    s = SimState(arch='AMD64')

    s.registers.store('rbx', 2)
    proc = SIM_PROCEDURES['testing']['retreg'](reg='rbx')
    succ = SimEngineProcedure().process(s, proc)
    rbx = succ.artifacts['procedure'].ret_expr
    nose.tools.assert_is(type(rbx), angr.state_plugins.SimActionObject)
    nose.tools.assert_equal(s.solver.eval(rbx), 2)
    nose.tools.assert_equal(rbx.reg_deps, { s.arch.registers['rbx'][0] })

if __name__ == '__main__':
    test_procedure_actions()
