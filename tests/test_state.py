import cle
import pickle
import gc
import os
import unittest

import claripy
import angr
from angr import SimState


binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")


class TestState(unittest.TestCase):
    def test_state(self):
        s = SimState(arch="AMD64")
        s.registers.store("sp", 0x7FFFFFFFFFF0000)
        assert s.solver.eval(s.registers.load("sp")) == 0x7FFFFFFFFFF0000

        s.stack_push(s.solver.BVV(b"ABCDEFGH"))
        assert s.solver.eval(s.registers.load("sp")) == 0x7FFFFFFFFFEFFF8
        s.stack_push(s.solver.BVV(b"IJKLMNOP"))
        assert s.solver.eval(s.registers.load("sp")) == 0x7FFFFFFFFFEFFF0

        a = s.stack_pop()
        assert s.solver.eval(s.registers.load("sp")) == 0x7FFFFFFFFFEFFF8
        assert s.solver.eval(a, cast_to=bytes) == b"IJKLMNOP"

        b = s.stack_pop()
        assert s.solver.eval(s.registers.load("sp")) == 0x7FFFFFFFFFF0000
        assert s.solver.eval(b, cast_to=bytes) == b"ABCDEFGH"

    def test_state_merge(self):
        a = SimState(arch="AMD64", mode="symbolic")
        a.memory.store(1, a.solver.BVV(42, 8))

        b = a.copy()
        c = b.copy()
        a.memory.store(2, a.memory.load(1, 1) + 1)
        b.memory.store(2, b.memory.load(1, 1) * 2)
        c.memory.store(2, c.memory.load(1, 1) / 2)

        # make sure the byte at 1 is right
        assert a.solver.eval(a.memory.load(1, 1)) == 42
        assert b.solver.eval(b.memory.load(1, 1)) == 42
        assert c.solver.eval(c.memory.load(1, 1)) == 42

        # make sure the byte at 2 is right
        assert a.solver.eval(a.memory.load(2, 1)) == 43
        assert b.solver.eval(b.memory.load(2, 1)) == 84
        assert c.solver.eval(c.memory.load(2, 1)) == 21

        # the byte at 2 should be unique for all before the merge
        assert a.solver.unique(a.memory.load(2, 1))
        assert b.solver.unique(b.memory.load(2, 1))
        assert c.solver.unique(c.memory.load(2, 1))

        # logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.DEBUG)
        m, merge_conditions, merging_occurred = a.merge(b, c)
        # logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.WARNING)

        assert merging_occurred
        # assert sorted(m.solver.eval_upto(merge_flag, 10)) == [ 0,1,2 ]
        assert len(merge_conditions) == 3

        # the byte at 2 should now *not* be unique for a
        assert not m.solver.unique(m.memory.load(2, 1))
        assert a.solver.unique(a.memory.load(2, 1))
        assert b.solver.unique(b.memory.load(2, 1))
        assert c.solver.unique(c.memory.load(2, 1))

        # the byte at 2 should have the three values
        self.assertSequenceEqual(sorted(m.solver.eval_upto(m.memory.load(2, 1), 10)), (21, 43, 84))

        # we should be able to select them by adding constraints
        a_a = m.copy()
        a_a.add_constraints(merge_conditions[0])
        assert a_a.solver.unique(a_a.memory.load(2, 1))
        assert a_a.solver.eval(a_a.memory.load(2, 1)) == 43

        a_b = m.copy()
        a_b.add_constraints(merge_conditions[1])
        assert a_b.solver.unique(a_b.memory.load(2, 1))
        assert a_b.solver.eval(a_b.memory.load(2, 1)) == 84

        a_c = m.copy()
        a_c.add_constraints(merge_conditions[2])
        assert a_c.solver.unique(a_c.memory.load(2, 1))
        assert a_c.solver.eval(a_c.memory.load(2, 1)) == 21

        # test different sets of plugins
        a = SimState(arch="AMD64", mode="symbolic")
        assert a.has_plugin("memory")
        assert a.has_plugin("registers")
        assert not a.has_plugin("libc")

        b = a.copy()
        a.get_plugin("libc")
        assert a.has_plugin("libc")
        assert not b.has_plugin("libc")
        c = a.copy().merge(b.copy())[0]
        d = b.copy().merge(a.copy())[0]
        assert c.has_plugin("libc")
        assert d.has_plugin("libc")

        # test merging posix with different open files (illegal!)
        a = SimState(arch="AMD64", mode="symbolic")
        b = a.copy()
        a.posix.open(b"/tmp/idk", 1)
        self.assertRaises(angr.errors.SimMergeError, lambda: a.copy().merge(b.copy()))

    def test_state_merge_static(self):
        # With abstract memory
        # Aligned memory merging
        a = SimState(arch="AMD64", mode="static")

        addr = a.solver.ValueSet(32, "global", 0, 8)
        a.memory.store(addr, a.solver.BVV(42, 32))
        # Clear a_locs, so further writes will not try to merge with value 42
        a.memory._regions["global"]._alocs = {}

        b = a.copy()
        c = a.copy()
        a.memory.store(addr, a.solver.BVV(50, 32), endness="Iend_LE")
        b.memory.store(addr, a.solver.BVV(60, 32), endness="Iend_LE")
        c.memory.store(addr, a.solver.BVV(70, 32), endness="Iend_LE")

        merged, _, _ = a.merge(b, c)
        actual = claripy.backends.vsa.convert(merged.memory.load(addr, 4, endness="Iend_LE"))
        expected = claripy.backends.vsa.convert(a.solver.SI(bits=32, stride=10, lower_bound=50, upper_bound=70))
        assert actual.identical(expected)

    def test_state_merge_3way(self):
        a = SimState(arch="AMD64", mode="symbolic")
        b = a.copy()
        c = a.copy()
        conds = [a.solver.BoolS("cond_0"), a.solver.BoolS("cond_1")]
        a.add_constraints(conds[0])
        b.add_constraints(a.solver.Not(conds[0]), conds[1])
        c.add_constraints(a.solver.Not(conds[0]), a.solver.Not(conds[1]))

        a.memory.store(0x400000, a.solver.BVV(8, 32))
        b.memory.store(0x400000, b.solver.BVV(9, 32))
        c.memory.store(0x400000, c.solver.BVV(10, 32))

        m, _, _ = a.merge(b)
        m, _, _ = m.merge(c)

        assert m.satisfiable(extra_constraints=(m.memory.load(0x400000, 4) == 8,))
        assert m.satisfiable(extra_constraints=(m.memory.load(0x400000, 4) == 9,))
        assert m.satisfiable(extra_constraints=(m.memory.load(0x400000, 4) == 10,))

    def test_state_merge_optimal_nostrongrefstate(self):
        # We do not specify the state option EFFICIENT_STATE_MERGING, and as a result, state histories do not store
        # strong # references to states. This will result in less efficient state merging since SimStateHistory will be
        # the only # state plugin that knows the common ancestor of all instances to merge. But it should still succeed.

        binary_path = os.path.join(binaries_base, "tests", "x86_64", "state_merge_0")
        p = angr.Project(binary_path, auto_load_libs=False)
        sm = p.factory.simulation_manager()

        sm.explore(find=0x400616, num_find=3)

        var_addr = 0x601044

        sm.merge(stash="found")
        s = sm.one_found
        culprit = s.mem[var_addr].dword.resolved

        for i in range(8, 11):
            assert i, s.solver.satisfiable(extra_constraints=(culprit == i,))

        assert not s.solver.satisfiable(extra_constraints=(culprit == 12,))

    def test_state_merge_optimal(self):
        # Unlike the above test case, EFFICIENT_STATE_MERGING is enabled here

        binary_path = os.path.join(binaries_base, "tests", "x86_64", "state_merge_0")
        p = angr.Project(binary_path, auto_load_libs=False)
        state = p.factory.blank_state(add_options={angr.sim_options.EFFICIENT_STATE_MERGING})
        sm = p.factory.simulation_manager(state)

        sm.explore(find=0x400616, num_find=3)

        var_addr = 0x601044

        sm.merge(stash="found")
        s = sm.one_found
        culprit = s.mem[var_addr].dword.resolved

        for i in range(8, 11):
            assert i, s.solver.satisfiable(extra_constraints=(culprit == i,))

        assert not s.solver.satisfiable(extra_constraints=(culprit == 12,))

    def test_state_pickle(self):
        s = SimState(arch="AMD64")
        s.memory.store(100, s.solver.BVV(0x4141414241414241424300, 88), endness="Iend_BE")
        s.regs.rax = 100

        sp = pickle.dumps(s)
        del s
        gc.collect()
        s = pickle.loads(sp)
        assert s.solver.eval(s.memory.load(100, 10), cast_to=bytes) == b"AAABAABABC"

    def test_global_condition(self):
        s = SimState(arch="AMD64")

        s.regs.rax = 10
        old_rax = s.regs.rax
        with s.with_condition(False):
            assert not s.solver.satisfiable()
            s.regs.rax = 20
        assert s._global_condition is None
        assert old_rax is s.regs.rax

        with s.with_condition(True):
            s.regs.rax = 20
        assert s._global_condition is None
        assert old_rax is not s.regs.rax
        assert s.solver.BVV(20, s.arch.bits) is s.regs.rax

        with s.with_condition(s.regs.rbx != 0):
            s.regs.rax = 25
        assert s._global_condition is None
        assert s.solver.BVV(25, s.arch.bits) is not s.regs.rax

        with s.with_condition(s.regs.rbx != 1):
            s.regs.rax = 30
        assert s._global_condition is None
        assert s.solver.BVV(30, s.arch.bits) is not s.regs.rax

        with s.with_condition(s.regs.rbx == 0):
            assert s.solver.eval_upto(s.regs.rbx, 10) == [0]
            assert s.solver.eval_upto(s.regs.rax, 10) == [30]
        with s.with_condition(s.regs.rbx == 1):
            assert s.solver.eval_upto(s.regs.rbx, 10) == [1]
            assert s.solver.eval_upto(s.regs.rax, 10) == [25]

    def test_successors_catch_arbitrary_interrupts(self):
        # int 0xd2 should fail on x86/amd64 since it's an unsupported interrupt
        block_bytes = b"\xcd\xd2"

        proj = angr.load_shellcode(block_bytes, "amd64")
        proj.loader.tls = cle.backends.tls.ELFThreadManager(proj.loader, proj.arch)
        proj.simos = angr.simos.SimLinux(proj)
        proj.simos.configure_project()
        state = proj.factory.blank_state(addr=0)
        simgr = proj.factory.simgr(state)

        simgr.step()

        assert (
            len(simgr.errored) == 0
        ), "The state should not go to the errored stash. Is AngrSyscallError handled in SimSuccessors?"
        assert len(simgr.unsat) == 1

    def test_bypass_errored_irstmt(self):
        # fild [esp+4]  will fail when ftop is unspecified
        # BYPASS_ERRORED_IRSTMT will suppress it

        block_bytes = b"\xdb\x44\x24\x04"

        proj = angr.load_shellcode(block_bytes, "x86")
        state = proj.factory.blank_state(
            addr=0,
            mode="fastpath",
            cle_memory_backer=proj.loader.memory,
            add_options={angr.sim_options.FAST_REGISTERS},
            remove_options={angr.sim_options.BYPASS_ERRORED_IRSTMT},
        )

        # destroy esp
        state.regs._esp = state.solver.BVS("unknown_rsp", 32)
        state.regs._ftop = state.solver.BVS("unknown_ftop", 32)

        # there should be one errored state if we step the state further without BYPASS_ERRORED_IRSTMT
        simgr = proj.factory.simgr(state)
        simgr.step()
        assert len(simgr.errored) == 1
        assert (
            str(simgr.errored[0].error) == "address not supported"
        ), "Does SimFastMemory support reading from a symbolic address?"

        # try it with BYPASS_ERRORED_IRSTMT
        state.options.add(angr.sim_options.BYPASS_ERRORED_IRSTMT)
        simgr = proj.factory.simgr(state)
        simgr.step()

        assert len(simgr.errored) == 0
        assert len(simgr.active) == 1


if __name__ == "__main__":
    unittest.main()
