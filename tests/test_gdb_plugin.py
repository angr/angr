import os
import logging
import nose
import angr

l = logging.getLogger("angr_tests")

this_file = os.path.dirname(os.path.realpath(__file__))
test_location = os.path.join(this_file, '..', '..', 'binaries', 'tests')
data_location = os.path.join(this_file, '..', '..', 'binaries', 'tests_data', 'test_gdb_plugin')

def test_gdb():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_gdb_plugin'))
    st = p.factory.blank_state()

    st.gdb.set_stack(os.path.join(data_location, "stack"), stack_top=0x7ffffffff000)
    st.gdb.set_heap(os.path.join(data_location, "heap"), heap_base = 0x601000)
    st.gdb.set_regs(os.path.join(data_location, "regs"))

    nose.tools.assert_equal(st.solver.eval(st.regs.rip), 0x4005b4)

    # Read the byte in memory at $sp + 8
    loc = st.solver.eval(st.regs.rsp) + 8
    val = st.memory.load(loc, 8, endness=st.arch.memory_endness)
    nose.tools.assert_equal(st.solver.eval(val), 0x00601010)

if __name__ == "__main__":
    test_gdb()
