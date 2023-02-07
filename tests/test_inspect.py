# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr
import pyvex
import claripy
import archinfo

from angr import SimState, BP_AFTER, BP_BEFORE, SIM_PROCEDURES, concretization_strategies
from angr.engines import ProcedureEngine, HeavyVEXMixin, SimInspectMixin


class InspectEngine(SimInspectMixin, HeavyVEXMixin):
    pass


class TestInspect(unittest.TestCase):
    def test_inspect(self):
        class counts:  # pylint:disable=no-init
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

        def act_mem_read(state):  # pylint:disable=unused-argument
            counts.mem_read += 1

        def act_mem_write(state):  # pylint:disable=unused-argument
            counts.mem_write += 1

        def act_reg_read(state):  # pylint:disable=unused-argument
            counts.reg_read += 1

        def act_reg_write(state):  # pylint:disable=unused-argument
            counts.reg_write += 1

        def act_tmp_read(state):  # pylint:disable=unused-argument
            counts.tmp_read += 1

        def act_tmp_write(state):  # pylint:disable=unused-argument
            counts.tmp_write += 1

        def act_expr(state):  # pylint:disable=unused-argument
            counts.expr += 1

        def act_statement(state):  # pylint:disable=unused-argument
            counts.statement += 1

        def act_instruction(state):  # pylint:disable=unused-argument
            counts.instruction += 1

        def act_variables(state):  # pylint:disable=unused-argument
            # print "CREATING:", state.inspect.symbolic_name
            counts.variables += 1

        #   def act_constraints(state): #pylint:disable=unused-argument
        #       counts.constraints += 1

        s = SimState(arch="AMD64", mode="symbolic")

        s.inspect.b("mem_write", when=BP_AFTER, action=act_mem_write)
        assert counts.mem_write == 0
        s.memory.store(100, s.solver.BVV(10, 32))
        assert counts.mem_write == 1

        s.inspect.b("mem_read", when=BP_AFTER, action=act_mem_read)
        s.inspect.b("mem_read", when=BP_AFTER, action=act_mem_read, mem_read_address=100)
        s.inspect.b("mem_read", when=BP_AFTER, action=act_mem_read, mem_read_address=123)
        s.inspect.b("mem_read", when=BP_BEFORE, action=act_mem_read, mem_read_length=3)
        assert counts.mem_read == 0
        s.memory.load(123, 4)
        s.memory.load(223, 3)
        assert counts.mem_read == 4

        s.inspect.b("reg_read", when=BP_AFTER, action=act_reg_read)
        assert counts.reg_read == 0
        s.registers.load(16, size=8)
        assert counts.reg_read == 1

        s.inspect.b("reg_write", when=BP_AFTER, action=act_reg_write)
        assert counts.reg_write == 0
        s.registers.store(16, s.solver.BVV(10, 32))
        assert counts.reg_write == 1
        assert counts.mem_write == 1
        assert counts.mem_read == 4
        assert counts.reg_read == 1

        s.inspect.b("tmp_read", when=BP_AFTER, action=act_tmp_read, tmp_read_num=0)
        s.inspect.b("tmp_write", when=BP_AFTER, action=act_tmp_write, tmp_write_num=0)
        s.inspect.b("expr", when=BP_AFTER, action=act_expr, expr_result=1016)
        s.inspect.b("statement", when=BP_AFTER, action=act_statement)
        s.inspect.b("instruction", when=BP_AFTER, action=act_instruction, instruction=1001)
        s.inspect.b("instruction", when=BP_AFTER, action=act_instruction, instruction=1000)
        irsb = pyvex.IRSB(b"\x90\x90\x90\x90\xeb\x0a", mem_addr=1000, arch=archinfo.ArchAMD64(), opt_level=0)
        irsb.pp()
        InspectEngine(None).process(s, irsb=irsb)
        assert counts.reg_write == 7
        assert counts.reg_read == 2
        assert counts.tmp_write == 1
        assert counts.tmp_read == 1
        assert counts.expr == 3
        assert counts.statement == 11
        assert counts.instruction == 2
        assert counts.constraints == 0
        assert counts.mem_write == 1
        assert counts.mem_read == 4

        s = SimState(arch="AMD64", mode="symbolic")
        s.inspect.b("symbolic_variable", when=BP_AFTER, action=act_variables)
        s.memory.load(0, 10)
        assert counts.variables == 1

    def test_inspect_exit(self):
        class counts:  # pylint:disable=no-init
            exit_before = 0
            exit_after = 0

        def handle_exit_before(state):
            counts.exit_before += 1
            exit_target = state.inspect.exit_target
            assert state.solver.eval(exit_target) == 0x3F8
            # change exit target
            state.inspect.exit_target = 0x41414141
            assert state.inspect.exit_jumpkind == "Ijk_Boring"
            assert state.inspect.exit_guard.is_true()

        def handle_exit_after(state):  # pylint:disable=unused-argument
            counts.exit_after += 1

        s = SimState(arch="AMD64", mode="symbolic")
        irsb = pyvex.IRSB(b"\x90\x90\x90\x90\xeb\x0a", mem_addr=1000, arch=archinfo.ArchAMD64())

        # break on exit
        s.inspect.b("exit", BP_BEFORE, action=handle_exit_before)
        s.inspect.b("exit", BP_AFTER, action=handle_exit_after)

        # step it
        succ = HeavyVEXMixin(None).process(s, irsb=irsb).flat_successors

        # check
        assert succ[0].solver.eval(succ[0].ip) == 0x41414141
        assert counts.exit_before == 1
        assert counts.exit_after == 1

    def test_inspect_syscall(self):
        class counts:  # pylint:disable=no-init
            exit_before = 0
            exit_after = 0

        def handle_syscall_before(state):
            counts.exit_before += 1
            syscall_name = state.inspect.syscall_name
            assert syscall_name == "close"

        def handle_syscall_after(state):
            counts.exit_after += 1
            syscall_name = state.inspect.syscall_name
            assert syscall_name == "close"

        s = SimState(arch="AMD64", mode="symbolic")
        # set up to call so syscall close
        s.regs.rax = 3
        s.regs.rdi = 2

        # break on syscall
        s.inspect.b("syscall", BP_BEFORE, action=handle_syscall_before)
        s.inspect.b("syscall", BP_AFTER, action=handle_syscall_after)

        # step it
        proc = SIM_PROCEDURES["posix"]["close"](is_syscall=True)
        ProcedureEngine(None).process(s, procedure=proc, ret_to=s.ip)

        # check counts
        assert counts.exit_before == 1
        assert counts.exit_after == 1

    def test_inspect_concretization(self):
        # some values for the test
        x = claripy.BVS("x", 64)
        y = claripy.BVS("y", 64)

        #
        # This tests concretization-time address redirection.
        #

        def change_symbolic_target(state):
            if state.inspect.address_concretization_action == "store":
                state.inspect.address_concretization_expr = claripy.BVV(0x1000, state.arch.bits)

        s = SimState(arch="AMD64")
        s.inspect.b("address_concretization", BP_BEFORE, action=change_symbolic_target)
        s.memory.store(x, "A")
        assert list(s.solver.eval_upto(x, 10)) == [0x1000]
        assert list(s.solver.eval_upto(s.memory.load(0x1000, 1), 10)) == [0x41]

        #
        # This tests disabling constraint adding through siminspect -- the write still happens
        #

        def dont_add_constraints(state):
            state.inspect.address_concretization_add_constraints = False

        s = SimState(arch="AMD64")
        s.inspect.b("address_concretization", BP_BEFORE, action=dont_add_constraints)
        s.memory.store(x, "A")
        assert len(s.solver.eval_upto(x, 10)) == 10

        #
        # This tests raising an exception if symbolic concretization fails (i.e., if the address
        # is too unconstrained). The write aborts.
        #

        class UnconstrainedAbort(Exception):
            def __init__(self, message, state):
                Exception.__init__(self, message)
                self.state = state

        def abort_unconstrained(state):
            print(state.inspect.address_concretization_strategy, state.inspect.address_concretization_result)
            if (
                isinstance(
                    state.inspect.address_concretization_strategy,
                    concretization_strategies.SimConcretizationStrategyRange,
                )
                and state.inspect.address_concretization_result is None
            ):
                raise UnconstrainedAbort("uh oh", state)

        s = SimState(arch="AMD64")
        s.memory.write_strategies.insert(0, concretization_strategies.SimConcretizationStrategyRange(128))
        s.memory._write_address_range = 1
        s.memory._write_address_range_approx = 1
        s.add_constraints(y == 10)
        s.inspect.b("address_concretization", BP_AFTER, action=abort_unconstrained)
        s.memory.store(y, "A")
        assert list(s.solver.eval_upto(s.memory.load(y, 1), 10)) == [0x41]

        try:
            s.memory.store(x, "A")
            print("THIS SHOULD NOT BE REACHED")
            assert False
        except UnconstrainedAbort as e:
            assert e.state.memory is s.memory

    def test_inspect_engine_process(self):
        p = angr.Project(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "x86_64", "fauxware"
            ),
            auto_load_libs=False,
        )

        def check_first_symbolic_fork(state):
            succs = state.inspect.sim_successors.successors
            succ_addr = [hex(s.addr) for s in succs]
            assert len(succ_addr) == 2
            assert "0x400692L" in succ_addr
            assert "0x400699L" in succ_addr
            print("Fork after:", hex(state.addr))
            print("Successors:", succ_addr)

        def check_second_symbolic_fork(state):
            succs = state.inspect.sim_successors.successors
            succ_addr = [hex(s.addr) for s in succs]
            assert len(succ_addr) == 2
            assert "0x4006dfL" in succ_addr
            assert "0x4006e6L" in succ_addr
            print("Fork after:", hex(state.addr))
            print("Successors:", succ_addr)

        def first_symbolic_fork(state):
            return hex(state.addr) == "0x40068eL" and isinstance(state.inspect.sim_engine, HeavyVEXMixin)
            # TODO: I think this latter check is meaningless with the eleventh hour refactor

        def second_symbolic_fork(state):
            return hex(state.addr) == "0x4006dbL" and isinstance(state.inspect.sim_engine, HeavyVEXMixin)

        def check_state(state):
            assert hex(state.inspect.sim_successors.addr) in ("0x40068eL", "0x4006dbL")

        state = p.factory.entry_state(addr=p.loader.find_symbol("main").rebased_addr)
        pg = p.factory.simulation_manager(state)
        state.inspect.b("engine_process", when=BP_BEFORE, action=check_state, condition=first_symbolic_fork)
        state.inspect.b(
            "engine_process", when=BP_AFTER, action=check_first_symbolic_fork, condition=first_symbolic_fork
        )
        pg.run()

        state = p.factory.entry_state(addr=p.loader.find_symbol("main").rebased_addr)
        pg = p.factory.simulation_manager(state)
        state.inspect.b("engine_process", when=BP_BEFORE, action=check_state, condition=second_symbolic_fork)
        state.inspect.b(
            "engine_process", when=BP_AFTER, action=check_second_symbolic_fork, condition=second_symbolic_fork
        )
        pg.run()


if __name__ == "__main__":
    unittest.main()
