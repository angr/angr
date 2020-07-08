import claripy
import angr


def test_symbolic_stack_base_address():
    state = angr.SimState(arch="amd64", mode="symbolic", add_options={angr.options.REPLACEMENT_SOLVER})

    sp = claripy.BVS("stack_pointer", state.arch.bits)
    sp_value_0 = claripy.BVV(0x7fff0000, state.arch.bits)
    state.regs._sp = sp
    state.solver._solver.add_replacement(sp, sp_value_0, invalidate_cache=False)

    # round 0: write values to the stack
    v = claripy.BVV(0x1a2b3c4d, 32)
    state.memory.store(state.regs._sp, v, endness="Iend_LE")
    expr = state.memory.load(state.regs._sp, 4, endness="Iend_LE")
    assert state.solver.eval(expr) == v.args[0]

    # round 1: rebase the stack using the concrete stack address
    v = claripy.BVV(0xfefefefe0c0c0c0c, 64)
    state.memory.store(0x7fff0004, v, endness="Iend_LE")
    expr = state.memory.load(state.regs._sp + 4, 8, endness="Iend_LE")
    assert state.solver.eval(expr) == v.args[0]


def test_rebasing_stack():
    state = angr.SimState(arch="amd64", mode="symbolic", add_options={angr.options.REPLACEMENT_SOLVER})
    state.regs._sp = state.arch.initial_sp

    state.stack_push(claripy.BVV(0x1234, state.arch.bits))
    state.stack_push(claripy.BVV(0x5678, state.arch.bits))
    state.stack_push(claripy.BVV(0xabcd, state.arch.bits))
    state.stack_push(claripy.BVV(0xc0debabe, state.arch.bits))

    assert state.solver.eval(state.memory.load(state.arch.initial_sp - 8, size=8, endness="Iend_LE")) == 0x1234
    assert state.solver.eval(state.memory.load(state.arch.initial_sp - 16, size=8, endness="Iend_LE")) == 0x5678
    assert state.solver.eval(state.memory.load(state.arch.initial_sp - 24, size=8, endness="Iend_LE")) == 0xabcd
    assert state.solver.eval(state.memory.load(state.arch.initial_sp - 32, size=8, endness="Iend_LE")) == 0xc0debabe

    state.rb_stack.rebase(0x900000)
    assert state.rb_stack.bp_value == 0x900000
    assert state.solver.eval(state.memory.load(0x900000 - 8, size=8, endness="Iend_LE")) == 0x1234
    assert state.solver.eval(state.memory.load(0x900000 - 16, size=8, endness="Iend_LE")) == 0x5678
    assert state.solver.eval(state.memory.load(0x900000 - 24, size=8, endness="Iend_LE")) == 0xabcd
    assert state.solver.eval(state.memory.load(0x900000 - 32, size=8, endness="Iend_LE")) == 0xc0debabe


if __name__ == "__main__":
    test_symbolic_stack_base_address()
    test_rebasing_stack()
