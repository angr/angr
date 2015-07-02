import nose
import simuvex
import pyvex
import archinfo

from simuvex import SimState

#@nose.tools.timed(10)
def broken_inspect():
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
#   def act_constraints(state): #pylint:disable=unused-argument
#       counts.constraints += 1


    s = SimState(arch="AMD64", mode="symbolic")

    s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_AFTER, action=act_mem_write))
    nose.tools.assert_equals(counts.mem_write, 0)
    s.store_mem(100, s.se.BitVecVal(10, 32))
    nose.tools.assert_equals(counts.mem_write, 1)

    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read))
    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read, mem_read_address=100))
    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read, mem_read_address=123))
    nose.tools.assert_equals(counts.mem_read, 0)
    s.mem_expr(123, 4)
    nose.tools.assert_equals(counts.mem_read, 2)

    s.inspect.add_breakpoint('reg_read', simuvex.BP(simuvex.BP_AFTER, action=act_reg_read))
    nose.tools.assert_equals(counts.reg_read, 0)
    s.reg_expr(16)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.add_breakpoint('reg_write', simuvex.BP(simuvex.BP_AFTER, action=act_reg_write))
    nose.tools.assert_equals(counts.reg_write, 0)
    s.store_reg(16, s.se.BitVecVal(10, 32))
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 2)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.add_breakpoint('tmp_read', simuvex.BP(simuvex.BP_AFTER, action=act_tmp_read, tmp_read_num=0))
    s.inspect.add_breakpoint('tmp_write', simuvex.BP(simuvex.BP_AFTER, action=act_tmp_write, tmp_write_num=0))
    s.inspect.add_breakpoint('expr', simuvex.BP(simuvex.BP_AFTER, action=act_expr, expr=1016, expr_unique=False))
    s.inspect.add_breakpoint('statement', simuvex.BP(simuvex.BP_AFTER, action=act_statement))
    s.inspect.add_breakpoint('instruction', simuvex.BP(simuvex.BP_AFTER, action=act_instruction, instruction=1001))
    s.inspect.add_breakpoint('instruction', simuvex.BP(simuvex.BP_AFTER, action=act_instruction, instruction=1000))
    irsb = pyvex.IRSB("\x90\x90\x90\x90\xeb\x0a", mem_addr=1000, arch=archinfo.ArchAMD64())
    irsb.pp()
    simuvex.SimIRSB(s, irsb)
    nose.tools.assert_equals(counts.reg_write, 6)
    nose.tools.assert_equals(counts.reg_read, 2)
    nose.tools.assert_equals(counts.tmp_write, 1)
    nose.tools.assert_equals(counts.tmp_read, 1)
    nose.tools.assert_equals(counts.expr, 3) # one for the Put, one for the WrTmp, and one to get the next address to jump to
    nose.tools.assert_equals(counts.statement, 26)
    nose.tools.assert_equals(counts.instruction, 2)
    nose.tools.assert_equals(counts.constraints, 0)

    # final tally
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 2)
    nose.tools.assert_equals(counts.reg_write, 6)
    nose.tools.assert_equals(counts.reg_read, 2)
    nose.tools.assert_equals(counts.tmp_write, 1)
    nose.tools.assert_equals(counts.tmp_read, 1)
    nose.tools.assert_equals(counts.expr, 3)
    nose.tools.assert_equals(counts.statement, 26)
    nose.tools.assert_equals(counts.instruction, 2)
    nose.tools.assert_equals(counts.constraints, 0)

