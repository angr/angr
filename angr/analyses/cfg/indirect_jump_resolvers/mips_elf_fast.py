# pylint:disable=too-many-boolean-expressions,global-statement
from typing import Dict, Optional, Tuple, TYPE_CHECKING
import logging

import pyvex
import archinfo


from .... import options, BP_BEFORE
from ....blade import Blade
from ....annocfg import AnnotatedCFG
from ....exploration_techniques import Slicecutor
from ....utils.constants import DEFAULT_STATEMENT
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
    from angr.block import Block


l = logging.getLogger(name=__name__)

PROFILING = False
HITS_CASE_0, HITS_CASE_1, MISSES = 0, 0, 0


def enable_profiling():
    global PROFILING, HITS_CASE_0, HITS_CASE_1, MISSES
    PROFILING = True
    HITS_CASE_0 = 0
    HITS_CASE_1 = 0
    MISSES = 0


def disable_profiling():
    global PROFILING
    PROFILING = False


class OverwriteTmpValueCallback:
    """
    Overwrites temporary values during resolution
    """

    def __init__(self, gp_value):
        self.gp_value = gp_value

    def overwrite_tmp_value(self, state):
        state.inspect.tmp_write_expr = state.solver.BVV(self.gp_value, state.arch.bits)


class MipsElfFastResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver for R9-based indirect function calls in MIPS ELFs.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(
            self.project.arch,
            (
                archinfo.ArchMIPS32,
                archinfo.ArchMIPS64,
            ),
        ):
            return False
        return True

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        """
        Wrapper for _resolve that slowly increments the max_depth used by Blade for finding sources
        until we can resolve the addr or we reach the default max_depth

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :param str jumpkind: The jumpkind.
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """
        for max_level in range(2, 4):
            resolved, resolved_targets = self._resolve(cfg, addr, func_addr, block, jumpkind, max_level=max_level)
            if resolved:
                return resolved, resolved_targets
        return False, []

    def _resolve(self, cfg, addr, func_addr, block, jumpkind, max_level):  # pylint:disable=unused-argument
        """
        Resolves the indirect jump in MIPS ELF binaries where all external function calls are indexed using gp.

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :param str jumpkind: The jumpkind.
        :param int max_level: maximum level for Blade to resolve when looking for sources
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """

        global HITS_CASE_0, HITS_CASE_1, MISSES

        project = self.project

        b = Blade(
            cfg.graph,
            addr,
            -1,
            cfg=cfg,
            project=project,
            ignore_sp=True,
            ignore_bp=True,
            ignored_regs=("gp",),
            cross_insn_opt=False,
            stop_at_calls=True,
            max_level=max_level,
            include_imarks=False,
        )

        func = cfg.kb.functions.function(addr=func_addr)
        gp_value = func.info.get("gp", None)

        # see if gp is used on this slice at all
        gp_used = self._is_gp_used_on_slice(project, b)
        if gp_used and gp_value is None:
            # this might a special case: gp is only used once in this function, and it can be initialized right
            # before its use site.
            # however, it should have been determined in CFGFast
            # cannot determine the value of gp. quit
            l.warning("Failed to determine value of register gp for function %#x.", func.addr)
            return False, []

        if gp_value is not None:
            target = self._try_handle_simple_case_0(gp_value, b)
            if target is not None:
                if PROFILING:
                    HITS_CASE_0 += 1
                    # print(f"hit/miss: {HITS_CASE_0 + HITS_CASE_1}/{MISSES}, {HITS_CASE_0}|{HITS_CASE_1}")
                return True, [target]
            target = self._try_handle_simple_case_1(gp_value, b)
            if target is not None:
                if PROFILING:
                    HITS_CASE_1 += 1
                    # print(f"hit/miss: {HITS_CASE_0 + HITS_CASE_1}/{MISSES}, {HITS_CASE_0}|{HITS_CASE_1}")
                return True, [target]

        if PROFILING:
            MISSES += 1
            # print(f"hit/miss: {HITS_CASE_0 + HITS_CASE_1}/{MISSES}, {HITS_CASE_0}|{HITS_CASE_1}")

        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]
        if not sources:
            return False, []

        source = sources[0]
        source_addr = source[0]
        annotated_cfg = AnnotatedCFG(project, None, detect_loops=False)
        annotated_cfg.from_digraph(b.slice)

        state = project.factory.blank_state(
            addr=source_addr,
            mode="fastpath",
            remove_options=options.refs,
            # suppress unconstrained stack reads for `gp`
            add_options={
                options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                options.NO_CROSS_INSN_OPT,
            },
        )
        state.regs._t9 = func_addr

        if gp_used:
            # Special handling for cases where `gp` is stored on the stack
            gp_offset = project.arch.registers["gp"][0]
            self._set_gp_load_callback(state, b, project, gp_offset, gp_value)
            state.regs._gp = gp_value

        simgr = self.project.factory.simulation_manager(state)
        simgr.use_technique(Slicecutor(annotated_cfg, force_sat=True))
        simgr.run()

        if simgr.cut:
            # pick the successor that is cut right after executing `addr`
            try:
                target_state = next(iter(cut for cut in simgr.cut if cut.history.addr == addr))
            except StopIteration:
                l.info("Indirect jump at %#x cannot be resolved by %s.", addr, repr(self))
                return False, []
            target = target_state.addr

            if self._is_target_valid(cfg, target) and target != func_addr:
                l.debug("Indirect jump at %#x is resolved to target %#x.", addr, target)
                return True, [target]

            l.info("Indirect jump at %#x is resolved to target %#x, which seems to be invalid.", addr, target)
            return False, []

        l.info("Indirect jump at %#x cannot be resolved by %s.", addr, repr(self))
        return False, []

    def _try_handle_simple_case_0(self, gp: int, blade: Blade) -> Optional[int]:
        # we only attempt to support the following case:
        #  + A | t37 = GET:I32(gp)
        #  + B | t36 = Add32(t37,0xffff8624)
        #  + C | t38 = LDbe:I32(t36)
        #  + D | PUT(t9) = t38
        #  + E | t8 = GET:I32(t9)
        #  Next: t8

        nodes_with_no_outedges = []
        for node in blade.slice.nodes():
            if blade.slice.out_degree(node) == 0:
                nodes_with_no_outedges.append(node)
        if len(nodes_with_no_outedges) != 1:
            return None

        end_node = nodes_with_no_outedges[0]
        if end_node[-1] != DEFAULT_STATEMENT:
            return None

        end_block = self.project.factory.block(end_node[0], cross_insn_opt=blade._cross_insn_opt).vex
        if not isinstance(end_block.next, pyvex.IRExpr.RdTmp):
            return None
        next_tmp = end_block.next.tmp

        # step backward

        # E
        previous_node = self._previous_node(blade, end_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.WrTmp) or not isinstance(stmt.data, pyvex.IRExpr.Get):
            return None
        if stmt.tmp != next_tmp:
            return None
        if stmt.data.offset != self.project.arch.registers["t9"][0]:
            return None

        # D
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.Put) or not isinstance(stmt.data, pyvex.IRExpr.RdTmp):
            return None
        if stmt.offset != self.project.arch.registers["t9"][0]:
            return None
        data_tmp = stmt.data.tmp

        # C
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or not isinstance(stmt.data, pyvex.IRExpr.Load)
            or not isinstance(stmt.data.addr, pyvex.IRExpr.RdTmp)
        ):
            return None
        if stmt.tmp != data_tmp:
            return None
        addr_tmp = stmt.data.addr.tmp

        # B
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or stmt.tmp != addr_tmp
            or not isinstance(stmt.data, pyvex.IRExpr.Binop)
            or stmt.data.op != "Iop_Add32"
            or not isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
            or not isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
        ):
            return None
        add_tmp = stmt.data.args[0].tmp
        add_const = stmt.data.args[1].con.value

        # A
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or stmt.tmp != add_tmp
            or not isinstance(stmt.data, pyvex.IRExpr.Get)
        ):
            return None
        if stmt.data.offset != self.project.arch.registers["gp"][0]:
            return None

        # matching complete
        addr = (gp + add_const) & 0xFFFF_FFFF
        try:
            target = self.project.loader.memory.unpack_word(addr, size=4)
            return target
        except KeyError:
            return None

    def _try_handle_simple_case_1(self, gp: int, blade: Blade) -> Optional[int]:
        # we only attempt to support the following case:
        #  + A | t22 = GET:I32(gp)
        #  + B | t21 = Add32(t22,0xffff8020)
        #  + C | t23 = LDbe:I32(t21)
        #  + D | PUT(t9) = t23
        #  + E | t27 = GET:I32(t9)
        #  + F | t26 = Add32(t27,0x00007cec)
        #  + G | PUT(t9) = t26
        #  + H | t4 = GET:I32(t9)
        #  + Next: t4

        nodes_with_no_outedges = []
        for node in blade.slice.nodes():
            if blade.slice.out_degree(node) == 0:
                nodes_with_no_outedges.append(node)
        if len(nodes_with_no_outedges) != 1:
            return None

        end_node = nodes_with_no_outedges[0]
        if end_node[-1] != DEFAULT_STATEMENT:
            return None

        end_block = self.project.factory.block(end_node[0], cross_insn_opt=blade._cross_insn_opt).vex
        if not isinstance(end_block.next, pyvex.IRExpr.RdTmp):
            return None
        next_tmp = end_block.next.tmp

        # step backward

        # H
        previous_node = self._previous_node(blade, end_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.WrTmp) or not isinstance(stmt.data, pyvex.IRExpr.Get):
            return None
        if stmt.tmp != next_tmp:
            return None
        if stmt.data.offset != self.project.arch.registers["t9"][0]:
            return None

        # G
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.Put) or not isinstance(stmt.data, pyvex.IRExpr.RdTmp):
            return None
        if stmt.offset != self.project.arch.registers["t9"][0]:
            return None
        t9_tmp_G = stmt.data.tmp

        # F
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or not stmt.tmp == t9_tmp_G
            or not isinstance(stmt.data, pyvex.IRExpr.Binop)
            or stmt.data.op != "Iop_Add32"
            or not isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
            or not isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
        ):
            return None
        t9_tmp_F = stmt.data.args[0].tmp
        t9_add_const = stmt.data.args[1].con.value

        # E
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.WrTmp) or not isinstance(stmt.data, pyvex.IRExpr.Get):
            return None
        if stmt.tmp != t9_tmp_F:
            return None
        if stmt.data.offset != self.project.arch.registers["t9"][0]:
            return None

        # D
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if not isinstance(stmt, pyvex.IRStmt.Put) or not isinstance(stmt.data, pyvex.IRExpr.RdTmp):
            return None
        if stmt.offset != self.project.arch.registers["t9"][0]:
            return None
        t9_tmp_D = stmt.data.tmp

        # C
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or not isinstance(stmt.data, pyvex.IRExpr.Load)
            or not isinstance(stmt.data.addr, pyvex.IRExpr.RdTmp)
        ):
            return None
        if stmt.tmp != t9_tmp_D:
            return None
        addr_tmp = stmt.data.addr.tmp

        # B
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or stmt.tmp != addr_tmp
            or not isinstance(stmt.data, pyvex.IRExpr.Binop)
            or stmt.data.op != "Iop_Add32"
            or not isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
            or not isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
        ):
            return None
        add_tmp = stmt.data.args[0].tmp
        add_const = stmt.data.args[1].con.value

        # A
        previous_node = self._previous_node(blade, previous_node)
        if previous_node is None:
            return None
        stmt = end_block.statements[previous_node[1]]
        if (
            not isinstance(stmt, pyvex.IRStmt.WrTmp)
            or stmt.tmp != add_tmp
            or not isinstance(stmt.data, pyvex.IRExpr.Get)
        ):
            return None
        if stmt.data.offset != self.project.arch.registers["gp"][0]:
            return None

        # matching complete
        addr = (gp + add_const) & 0xFFFF_FFFF
        try:
            target_0 = self.project.loader.memory.unpack_word(addr, size=4)
            target = (target_0 + t9_add_const) & 0xFFFF_FFFF
            return target
        except KeyError:
            return None

    @staticmethod
    def _previous_node(blade: Blade, curr_node: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        if blade.slice.in_degree(curr_node) != 1:
            return None
        nn = next(iter(blade.slice.predecessors(curr_node)))
        if nn[0] != curr_node[0]:
            return None
        return nn

    @staticmethod
    def _set_gp_load_callback(state, blade, project, gp_offset, gp_value):
        tmps = {}
        for block_addr_in_slice in {slice_node[0] for slice_node in blade.slice.nodes()}:
            for stmt in project.factory.block(block_addr_in_slice, cross_insn_opt=False).vex.statements:
                if isinstance(stmt, pyvex.IRStmt.WrTmp) and isinstance(stmt.data, pyvex.IRExpr.Load):
                    # Load from memory to a tmp - assuming it's loading from the stack
                    tmps[stmt.tmp] = "stack"
                elif isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == gp_offset:
                    if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                        tmp_offset = stmt.data.tmp  # pylint:disable=cell-var-from-loop
                        if tmps.get(tmp_offset, None) == "stack":
                            # found the load from stack
                            # we must make sure value of that temporary variable equals to the correct gp value
                            state.inspect.make_breakpoint(
                                "tmp_write",
                                when=BP_BEFORE,
                                condition=(
                                    lambda s, bbl_addr_=block_addr_in_slice, tmp_offset_=tmp_offset: s.scratch.bbl_addr
                                    == bbl_addr_
                                    and s.inspect.tmp_write_num == tmp_offset_
                                ),
                                action=OverwriteTmpValueCallback(gp_value).overwrite_tmp_value,
                            )
                            break

    @staticmethod
    def _is_gp_used_on_slice(project, b: Blade) -> bool:
        gp_offset = project.arch.registers["gp"][0]
        blocks_on_slice: Dict[int, "Block"] = {}
        for block_addr, block_stmt_idx in b.slice.nodes():
            if block_addr not in blocks_on_slice:
                blocks_on_slice[block_addr] = project.factory.block(block_addr, cross_insn_opt=False)
            block = blocks_on_slice[block_addr]
            if block_stmt_idx == DEFAULT_STATEMENT:
                if isinstance(block.vex.next, pyvex.IRExpr.Get) and block.vex.next.offset == gp_offset:
                    gp_used = True
                    break
            else:
                stmt = block.vex.statements[block_stmt_idx]
                if (
                    isinstance(stmt, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt.data, pyvex.IRExpr.Get)
                    and stmt.data.offset == gp_offset
                ):
                    gp_used = True
                    break
        else:
            gp_used = False

        return gp_used
