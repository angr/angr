import nose
import pyvex
import simuvex
import claripy
import archinfo

def test_inspect():
    class counts: #pylint:disable=no-init
        mem_read = 0
        mem_write = 0
        reg_read = 0
        reg_write = 0
        tmp_read = 0
        tmp_write = 0
        expr = 0
        statement = 0
        instruction = 0
        constraints = 0
        variables = 0

    def act_mem_read(state): #pylint:disable=unused-argument
        counts.mem_read += 1
    def act_mem_write(state): #pylint:disable=unused-argument
        counts.mem_write += 1
    def act_reg_read(state): #pylint:disable=unused-argument
        counts.reg_read += 1
    def act_reg_write(state): #pylint:disable=unused-argument
        counts.reg_write += 1
    def act_tmp_read(state): #pylint:disable=unused-argument
        counts.tmp_read += 1
    def act_tmp_write(state): #pylint:disable=unused-argument
        counts.tmp_write += 1
    def act_expr(state): #pylint:disable=unused-argument
        counts.expr += 1
    def act_statement(state): #pylint:disable=unused-argument
        counts.statement += 1
    def act_instruction(state): #pylint:disable=unused-argument
        counts.instruction += 1
    def act_variables(state): #pylint:disable=unused-argument
        #print "CREATING:", state.inspect.symbolic_name
        counts.variables += 1
#   def act_constraints(state): #pylint:disable=unused-argument
#       counts.constraints += 1


    s = simuvex.SimState(arch="AMD64", mode="symbolic")

    s.inspect.b('mem_write', when=simuvex.BP_AFTER, action=act_mem_write)
    nose.tools.assert_equals(counts.mem_write, 0)
    s.memory.store(100, s.se.BVV(10, 32))
    nose.tools.assert_equals(counts.mem_write, 1)

    s.inspect.b('mem_read', when=simuvex.BP_AFTER, action=act_mem_read)
    s.inspect.b('mem_read', when=simuvex.BP_AFTER, action=act_mem_read, mem_read_address=100)
    s.inspect.b('mem_read', when=simuvex.BP_AFTER, action=act_mem_read, mem_read_address=123)
    s.inspect.b('mem_read', when=simuvex.BP_BEFORE, action=act_mem_read, mem_read_length=3)
    nose.tools.assert_equals(counts.mem_read, 0)
    s.memory.load(123, 4)
    s.memory.load(223, 3)
    nose.tools.assert_equals(counts.mem_read, 4)

    s.inspect.b('reg_read', when=simuvex.BP_AFTER, action=act_reg_read)
    nose.tools.assert_equals(counts.reg_read, 0)
    s.registers.load(16)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.b('reg_write', when=simuvex.BP_AFTER, action=act_reg_write)
    nose.tools.assert_equals(counts.reg_write, 0)
    s.registers.store(16, s.se.BVV(10, 32))
    nose.tools.assert_equals(counts.reg_write, 1)
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 4)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.b('tmp_read', when=simuvex.BP_AFTER, action=act_tmp_read, tmp_read_num=0)
    s.inspect.b('tmp_write', when=simuvex.BP_AFTER, action=act_tmp_write, tmp_write_num=0)
    s.inspect.b('expr', when=simuvex.BP_AFTER, action=act_expr, expr=1016, expr_unique=False)
    s.inspect.b('statement', when=simuvex.BP_AFTER, action=act_statement)
    s.inspect.b('instruction', when=simuvex.BP_AFTER, action=act_instruction, instruction=1001)
    s.inspect.b('instruction', when=simuvex.BP_AFTER, action=act_instruction, instruction=1000)
    irsb = pyvex.IRSB("\x90\x90\x90\x90\xeb\x0a", mem_addr=1000, arch=archinfo.ArchAMD64())
    irsb.pp()
    simuvex.SimIRSB(s, irsb)
    nose.tools.assert_equals(counts.reg_write, 7)
    nose.tools.assert_equals(counts.reg_read, 2)
    nose.tools.assert_equals(counts.tmp_write, 1)
    nose.tools.assert_equals(counts.tmp_read, 1)
    nose.tools.assert_equals(counts.expr, 3) # one for the Put, one for the WrTmp, and one to get the next address to jump to
    nose.tools.assert_equals(counts.statement, 26)
    nose.tools.assert_equals(counts.instruction, 2)
    nose.tools.assert_equals(counts.constraints, 0)
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 4)

    s = simuvex.SimState(arch="AMD64", mode="symbolic")
    s.inspect.b('symbolic_variable', when=simuvex.BP_AFTER, action=act_variables)
    s.memory.load(0, 10)
    nose.tools.assert_equals(counts.variables, 1)

def test_inspect_concretization():
    # some values for the test
    x = claripy.BVS('x', 64)
    y = claripy.BVS('y', 64)

    #
    # This tests concretization-time address redirection.
    #

    def change_symbolic_target(state):
        if state.inspect.address_concretization_action == 'store':
            state.inspect.address_concretization_expr = claripy.BVV(0x1000, state.arch.bits)

    s = simuvex.SimState()
    s.inspect.b('address_concretization', simuvex.BP_BEFORE, action=change_symbolic_target)
    s.memory.store(x, 'A')
    assert list(s.se.eval(x, 10)) == [ 0x1000 ]
    assert list(s.se.eval(s.memory.load(0x1000, 1), 10)) == [ 0x41 ]

    #
    # This tests disabling constraint adding through siminspect -- the write still happens
    #

    def dont_add_constraints(state):
        state.inspect.address_concretization_add_constraints = False

    s = simuvex.SimState()
    s.inspect.b('address_concretization', simuvex.BP_BEFORE, action=dont_add_constraints)
    s.memory.store(x, 'A')
    assert len(s.se.eval(x, 10)) == 10

    #
    # This tests raising an exception if symbolic concretization fails (i.e., if the address
    # is too unconstrained). The write aborts.
    #

    class UnconstrainedAbort(Exception):
        def __init__(self, message, state):
            Exception.__init__(self, message)
            self.state = state

    def abort_unconstrained(state):
        print state.inspect.address_concretization_strategy, state.inspect.address_concretization_result
        if state.inspect.address_concretization_strategy == 'symbolic' and state.inspect.address_concretization_result == None:
            raise UnconstrainedAbort("uh oh", state)

    s = simuvex.SimState()
    s.memory._default_write_strategy.insert(0, 'symbolic')
    s.memory._write_address_range = 1
    s.memory._write_address_range_approx = 1
    s.add_constraints(y == 10)
    s.inspect.b('address_concretization', simuvex.BP_AFTER, action=abort_unconstrained)
    s.memory.store(y, 'A')
    assert list(s.se.eval(s.memory.load(y, 1), 10)) == [ 0x41 ]

    try:
        s.memory.store(x, 'A')
        print "THIS SHOULD NOT BE REACHED"
        assert False
    except UnconstrainedAbort as e:
        assert e.state.memory is s.memory

if __name__ == '__main__':
    test_inspect_concretization()
    test_inspect()
