import nose
import angr
from angr.state_plugins.inspect import BP_BEFORE
import claripy

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def handle_mem_read(state):
    addr = state.inspect.mem_read_address
    size = state.inspect.mem_read_length
    cond = state.inspect.mem_read_condition
    fall = state.inspect.mem_read_fallback

    mem_val = state.memory.load(addr, size, endness='Iend_BE', condition=cond, fallback=fall, inspect=False)
    mem_var = state.solver.BVS("mem_load", mem_val.size())
    
    mem_expr = mem_var == mem_val
    state.add_constraints(mem_expr)

    state.inspect.mem_read_condition = False
    state.inspect.mem_read_fallback = mem_var

def test_read_inspect_fallback():
    proj = angr.Project(test_location + "/x86_64/memmove", load_options={'auto_load_libs': True})

    mgr = proj.factory.simulation_manager()
    mgr.stashes['active'][0].inspect.make_breakpoint('mem_read', BP_BEFORE, action=handle_mem_read)
    explorer = mgr.explore(find=[0x4005D7])
    s = explorer.found[0]
    load = s.memory.load(s.registers.load(16), 13)
    test_symbol = s.solver.BVS('test', 8)
    nose.tools.assert_equal(type(load), type(test_symbol))
    nose.tools.assert_equal(load.op, test_symbol.op)
    result = s.solver.eval(load, cast_to=bytes)
    nose.tools.assert_equal(result, b'very useful.\x00')

if __name__ == "__main__":
    test_read_inspect_fallback()

