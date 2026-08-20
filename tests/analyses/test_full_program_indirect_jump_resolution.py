#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestFullProgramIndirectJumpResolution(unittest.TestCase):
    @staticmethod
    def _run(binary_name):
        binary_path = os.path.join(test_location, "x86_64", binary_name)
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()
        fpijr = proj.analyses.FullProgramIndirectJumpResolution()
        return proj, cfg, fpijr

    @staticmethod
    def _union_of_resolutions(fpijr, func):
        """Return the union of all resolved target sets inside the given function,
        asserting there is at least one resolved site."""
        resolutions = fpijr.get_resolutions(func)
        assert resolutions, f"No resolved indirect jump/call sites in function {func.name}"
        targets: set[int] = set()
        for target_set in resolutions.values():
            targets |= target_set
        return targets

    def test_global_table(self):
        _, cfg, fpijr = self._run("fpijr_global_table")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_struct_array(self):
        _, cfg, fpijr = self._run("fpijr_struct_array")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("e0", "e1", "e2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_interproc(self):
        _, cfg, fpijr = self._run("fpijr_interproc")
        run_ops = cfg.kb.functions["run_ops"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, run_ops)
        assert targets == expected

    def test_local_cond(self):
        _, cfg, fpijr = self._run("fpijr_local_cond")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_global_callback_registered_at_runtime(self):
        # a callback passed to a registration function, stored by it into a global struct field, and invoked from a
        # third function: resolving it requires propagating the code pointer across all three functions and through
        # memory
        _, cfg, fpijr = self._run("fpijr_global_callback")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_callback_passed_as_argument(self):
        # a function pointer passed as an argument and invoked through the callee's parameter
        _, cfg, fpijr = self._run("fpijr_callback_param")
        apply_func = cfg.kb.functions["apply"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, apply_func)
        assert targets == expected

    def test_callback_array_registered_at_runtime(self):
        # callbacks registered at run time into a global array of structs and invoked through a run-time index; the
        # registration writes through a computed base (g_slots[i].cb) while the call site reads a folded constant
        # address, so both spellings must land in the same descriptor
        _, cfg, fpijr = self._run("fpijr_callback_array")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_static_vtable_chain(self):
        # devs[i]->drv->read: a chained dereference through statically initialized read-only structures. Every entry
        # of the device table must be considered, not just the first.
        _, cfg, fpijr = self._run("fpijr_static_vtable")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("r0", "r1")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_cortexm_firmware_callbacks(self):
        # A real firmware image: RIOT-OS on an NXP Kinetis Cortex-M MCU, built as Thumb code. Nearly every indirect
        # call in it goes through a callback that some other function registered at run time into a global struct or
        # array, so resolving them exercises the whole-program propagation end to end on real code. Function pointers
        # on this target carry the Thumb bit and are therefore odd addresses.
        binary_path = os.path.join(test_location, "armel", "fpijr_cortexm_console")
        proj = angr.Project(binary_path, auto_load_libs=False)
        assert proj.arch.name == "ARMCortexM"

        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        indirect_jumps = proj.kb.indirect_jumps
        unresolved_before = set(indirect_jumps.unresolved)

        fpijr = proj.analyses.FullProgramIndirectJumpResolution()

        # what was resolved has to reach the knowledge base, keyed by block address as that plugin is, and those
        # sites must no longer count as unresolved
        assert fpijr.resolved_indirect_jumps
        for site, targets in fpijr.resolved_indirect_jumps.items():
            node = cfg.model.get_any_node(site, anyaddr=True)
            assert node is not None
            assert targets <= set(indirect_jumps.resolved.get(node.addr, ()))
            assert node.addr not in indirect_jumps.unresolved
        assert len(indirect_jumps.unresolved) < len(unresolved_before)
        # this is the set Function consults when it decides whether its control flow is complete
        assert proj.kb.unresolved_indirect_jumps is indirect_jumps.unresolved

        def target_names(func_name):
            resolutions = fpijr.get_resolutions(cfg.kb.functions[func_name])
            assert resolutions, f"no resolved indirect call site in {func_name}"
            names = set()
            for target_set in resolutions.values():
                names |= {cfg.kb.functions[target].name for target in target_set}
            return names

        # The RTC interrupt chain, which spans three functions: rtc_set_alarm() hands rtc_cb to rtt_set_alarm(),
        # which stores it into a global; the interrupt handler loads that global and calls it; rtc_cb in turn calls
        # the handler that was registered the same way one level up.
        assert target_names("isr_rtc") == {"rtc_cb"}
        assert target_names("rtc_cb") == {"_alarm_handler"}

        # A UART receive callback registered at run time into a global array of per-device structs, reached through
        # a run-time index.
        assert target_names("irq_handler_uart") == {"isrpipe_write_one"}

        # Function pointers passed as arguments and invoked through the callee's parameter.
        assert target_names("_fwalk") == {"lflush"}
        assert target_names("_fwalk_reent") == {"_fflush_r"}

        # A refill callback kept in a struct, and a conditional pair of string-to-integer converters.
        assert target_names("__ssvfiscanf_r") == {"__ssrefill_r"}
        assert target_names("_scanf_i") == {"_strtol_r", "_strtoul_r"}

    def test_raw_firmware_image(self):
        # The same firmware as a raw flash image: no ELF header, no sections, no symbols. An image like this maps
        # only flash, so RAM and memory-mapped peripherals are not mapped at all, yet the callbacks registered into
        # them at run time still have to be tracked. The recovered targets must match what the ELF gives.
        binary_path = os.path.join(test_location, "armel", "fpijr_cortexm_console.bin")
        with open(binary_path, "rb") as fh:
            entry_point = int.from_bytes(fh.read(8)[4:8], "little")  # reset vector, out of the vector table
        proj = angr.Project(
            binary_path,
            auto_load_libs=False,
            main_opts={"backend": "blob", "arch": "ARMCortexM", "base_addr": 0, "entry_point": entry_point},
        )
        assert not proj.loader.main_object.sections

        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()
        fpijr = proj.analyses.FullProgramIndirectJumpResolution()
        resolved = fpijr.resolved_indirect_jumps

        # the same sites and targets the unstripped ELF resolves, by address since there are no symbols here:
        # isr_rtc -> rtc_cb -> _alarm_handler, the UART receive callback, and a callback passed as an argument
        assert resolved.get(0x29C9) == {0x26F1}
        assert resolved.get(0x2707) == {0x31E1}
        assert resolved.get(0x1673) == {0x12B5}
        assert resolved.get(0x43D3) == {0x6755}

        # nothing bogus may come out of a binary this bare
        for targets in resolved.values():
            for target in targets:
                assert cfg.kb.functions.contains_addr(target)

    def test_provenance(self):
        # every resolved target should come with the chain that carried the code pointer to the site
        _, cfg, fpijr = self._run("fpijr_global_callback")
        dispatch = cfg.kb.functions["dispatch"]
        site = next(iter(fpijr.get_resolutions(dispatch)))
        h1 = cfg.kb.functions["h1"].addr

        chain = fpijr.get_provenance(site, h1)
        kinds = [step.kind for step in chain]
        # main hands the pointer to register_cb, which stores it into the global that dispatch reads
        assert "argument" in kinds
        assert "store" in kinds
        assert kinds[-1] == "read"
        assert chain[-1].ins_addr == site
        # the argument step names the callee it was passed to
        argument_step = next(step for step in chain if step.kind == "argument")
        assert argument_step.callee_addr == cfg.kb.functions["register_cb"].addr

        # nothing resolved should be left unexplained
        for resolved_site, targets in fpijr.resolved_indirect_jumps.items():
            for target in targets:
                assert fpijr.get_provenance(resolved_site, target), f"no provenance for {resolved_site:#x}"

        described = fpijr.describe_provenance(site, h1)
        assert len(described) == len(chain)
        assert all(isinstance(line, str) and line for line in described)

    def test_provenance_of_a_static_table(self):
        # a target harvested out of initialized memory should say so, and name the address it came from
        _, cfg, fpijr = self._run("fpijr_global_table")
        dispatch = cfg.kb.functions["dispatch"]
        site = next(iter(fpijr.get_resolutions(dispatch)))
        f2 = cfg.kb.functions["f2"].addr
        chain = fpijr.get_provenance(site, f2)
        assert [step.kind for step in chain] == ["static", "read"]
        assert chain[0].addr is not None
        assert self._read_pointer(cfg, chain[0].addr) == f2

    @staticmethod
    def _read_pointer(cfg, addr):
        return cfg.project.loader.memory.unpack_word(addr, cfg.project.arch.bytes)

    def test_provenance_can_be_disabled(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_callback")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        with_tracking = proj.analyses.FullProgramIndirectJumpResolution()
        without_tracking = proj.analyses.FullProgramIndirectJumpResolution(track_provenance=False)

        # switching it off changes nothing about the answers, only about being able to explain them
        assert without_tracking.resolved_indirect_jumps == with_tracking.resolved_indirect_jumps
        assert not without_tracking.provenance
        site = next(iter(without_tracking.get_resolutions(cfg.kb.functions["dispatch"])))
        target = next(iter(without_tracking.resolved_indirect_jumps[site]))
        assert without_tracking.get_provenance(site, target) == []

    def test_knowledge_base_update_can_be_disabled(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_callback")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        indirect_jumps = proj.kb.indirect_jumps
        resolved_before = {addr: list(targets) for addr, targets in indirect_jumps.resolved.items()}

        untouched = proj.analyses.FullProgramIndirectJumpResolution(update_kb=False)
        assert untouched.resolved_indirect_jumps
        assert {addr: list(targets) for addr, targets in indirect_jumps.resolved.items()} == resolved_before

        # and with the default the same results do land in the knowledge base
        published = proj.analyses.FullProgramIndirectJumpResolution()
        for site, targets in published.resolved_indirect_jumps.items():
            node = cfg.model.get_any_node(site, anyaddr=True)
            assert targets <= set(indirect_jumps.resolved.get(node.addr, ()))

        # publishing twice must not pile the same targets up again
        counts = {addr: len(targets) for addr, targets in indirect_jumps.resolved.items()}
        proj.analyses.FullProgramIndirectJumpResolution()
        assert {addr: len(targets) for addr, targets in indirect_jumps.resolved.items()} == counts

    def test_progress_callback(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        updates = []

        def callback(percentage, text=None, **kwargs):
            updates.append((percentage, text, kwargs.get("analysis")))

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(progress_callback=callback)

        # progress must be reported, be monotonically non-decreasing, end at 100%, and expose the running instance
        assert updates
        percentages = [p for p, _, _ in updates]
        assert percentages == sorted(percentages)
        assert percentages[-1] == 100.0
        assert any(inst is fpijr for _, _, inst in updates)

        # low_priority must not change the result
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        assert self._union_of_resolutions(fpijr, dispatch) == expected

    def test_low_priority(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(low_priority=True)

        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        assert self._union_of_resolutions(fpijr, dispatch) == expected

    def test_abort(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        # abort from within the progress callback (as a host GUI would, via the passed-in analysis instance), after the
        # very first per-function update. The run must stop early yet still finalize a valid resolved_indirect_jumps.
        state = {"instance": None, "aborted_after": None}

        def callback(percentage, text=None, **kwargs):
            inst = kwargs.get("analysis")
            if inst is not None and state["instance"] is None:
                state["instance"] = inst
                inst.abort()
                state["aborted_after"] = percentage

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(progress_callback=callback)

        assert fpijr.should_abort
        assert state["instance"] is fpijr
        # aborting on the first tick means far fewer functions were analyzed than were selected
        assert len(fpijr._func_facts) < len(fpijr._selected_funcs)  # pylint:disable=protected-access
        # partial results must still be a valid dict
        assert isinstance(fpijr.resolved_indirect_jumps, dict)

    def test_abort_before_run_is_idempotent(self):
        _, _, fpijr = self._run("fpijr_global_table")
        # aborting a finished analysis is a harmless no-op and does not invalidate results
        fpijr.abort()
        assert fpijr.should_abort
        assert isinstance(fpijr.resolved_indirect_jumps, dict)


if __name__ == "__main__":
    unittest.main()
