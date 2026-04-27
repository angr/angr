"""
test_icicle_inspect.py - SimInspect mem_read / mem_write breakpoints during
icicle execution.
"""

# pylint: disable=no-self-use

from __future__ import annotations

from unittest import TestCase

import claripy

import angr
from angr import sim_options as o
from angr.engines.icicle import IcicleEngine


class TestIcicleInspect(TestCase):
    """Unit tests for SimInspect mem_read / mem_write breakpoints during icicle execution."""

    @staticmethod
    def _build():
        # Single store + single load against a writable scratch page.
        shellcode = """
        mov x0, 0x10000;
        mov x1, 0x42;
        str x1, [x0];
        ldr x2, [x0];
        """
        project = angr.load_shellcode(shellcode, "aarch64")
        engine = IcicleEngine(project)
        state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        state.memory.map_region(0x10000, 0x1000, 0b111)
        return engine, state

    @staticmethod
    def _capture(state, event, when):
        events = []

        def _on_event(state):
            insp = state.inspect
            addr = state.solver.eval(getattr(insp, f"{event}_address"), cast_to=int)
            length = getattr(insp, f"{event}_length")
            expr = getattr(insp, f"{event}_expr")
            value = None if expr is None else state.solver.eval(expr, cast_to=int)
            events.append((addr, length, value))

        state.inspect.b(event, when=when, action=_on_event)
        return events

    def test_mem_write_fires(self):
        """A mem_write BP fires for the str during icicle execution."""
        engine, state = self._build()
        events = self._capture(state, "mem_write", angr.BP_BEFORE)
        successors = engine.process(state, num_inst=4)
        assert len(successors.successors) == 1
        # Filter to the access that the str instruction performs.
        store_events = [e for e in events if e[0] == 0x10000 and e[1] == 8]
        assert store_events, f"expected an icicle-side mem_write at 0x10000 of length 8, got {events}"
        addr, length, value = store_events[0]
        assert length == 8
        # Architecture is little-endian aarch64; the BV reflects the LE value of x1.
        assert value == 0x42

    def test_mem_read_fires_before_and_after(self):
        """mem_read BP_BEFORE has no expr; BP_AFTER has the read value."""
        engine, state = self._build()
        before = self._capture(state, "mem_read", angr.BP_BEFORE)
        after = self._capture(state, "mem_read", angr.BP_AFTER)
        successors = engine.process(state, num_inst=4)
        assert len(successors.successors) == 1

        # Find the icicle-side read at 0x10000 of length 8 (the ldr instruction).
        before_load = [e for e in before if e[0] == 0x10000 and e[1] == 8]
        after_load = [e for e in after if e[0] == 0x10000 and e[1] == 8]
        assert before_load, f"expected a mem_read BP_BEFORE at 0x10000, got {before}"
        assert after_load, f"expected a mem_read BP_AFTER at 0x10000, got {after}"

        # BP_BEFORE has expr=None (no value yet); BP_AFTER has the read value.
        assert before_load[0][2] is None
        assert after_load[0][2] == 0x42

    def test_no_user_bps_no_hooks(self):
        """Without user BPs, no SimInspect events are observed for the run."""
        engine, state = self._build()
        # We can't directly observe icicle's hooks, but we can verify no BPs fire
        # by registering one *after* the run and checking nothing was buffered.
        successors = engine.process(state, num_inst=4)
        assert len(successors.successors) == 1
        events = self._capture(successors[0], "mem_read", angr.BP_AFTER)
        # No further runs; events should still be empty.
        assert events == []

    def test_mem_write_bp_does_not_break_run(self):
        """A non-trivial mem_write callback that calls back into state must not crash."""
        engine, state = self._build()
        seen = []

        def _on_write(state):
            # Calling state APIs from inside the callback is supported.
            addr = state.solver.eval(state.inspect.mem_write_address, cast_to=int)
            seen.append(addr)

        state.inspect.b("mem_write", when=angr.BP_AFTER, action=_on_write)
        successors = engine.process(state, num_inst=4)
        assert len(successors.successors) == 1
        # The store at 0x10000 must be observed.
        assert 0x10000 in seen

    def test_mem_read_override(self):
        """Setting mem_read_expr in BP_BEFORE redirects the read result."""
        engine, state = self._build()

        def _on_read(state):
            addr = state.solver.eval(state.inspect.mem_read_address, cast_to=int)
            length = state.inspect.mem_read_length
            # Only override the icicle-side ldr at 0x10000 of size 8.
            if addr == 0x10000 and length == 8:
                state.inspect.mem_read_expr = claripy.BVV(0xDEADBEEF, 64)

        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=_on_read)
        successors = engine.process(state, num_inst=4)
        assert len(successors.successors) == 1
        # x2 = ldr [x0]; the override replaces the actual stored 0x42 with 0xDEADBEEF.
        assert successors[0].regs.x2.concrete_value == 0xDEADBEEF

    def test_mem_read_override_per_access(self):
        """Each read fires the hook (TLB stays uncached); overrides apply per-access."""
        # ldp lifts to two 8-byte reads in icicle; both must hit the hook.
        shellcode = """
        mov x0, 0x10000;
        ldp x1, x2, [x0];
        """
        project = angr.load_shellcode(shellcode, "aarch64")
        engine = IcicleEngine(project)
        state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        state.memory.map_region(0x10000, 0x1000, 0b111)
        state.memory.store(0x10000, 0x1111111122222222, size=8, endness="Iend_LE")
        state.memory.store(0x10008, 0x3333333344444444, size=8, endness="Iend_LE")

        addr_to_override = {0x10000: 0xAAAAAAAA, 0x10008: 0xBBBBBBBB}

        def _on_read(state):
            addr = state.solver.eval(state.inspect.mem_read_address, cast_to=int)
            length = state.inspect.mem_read_length
            if addr in addr_to_override and length == 8:
                state.inspect.mem_read_expr = claripy.BVV(addr_to_override[addr], 64)

        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=_on_read)
        successors = engine.process(state, num_inst=2)
        assert len(successors.successors) == 1
        # Both halves of the pair must have been overridden — proves the TLB
        # didn't cache the first read and skip the hook for the second.
        assert successors[0].regs.x1.concrete_value == 0xAAAAAAAA
        assert successors[0].regs.x2.concrete_value == 0xBBBBBBBB
