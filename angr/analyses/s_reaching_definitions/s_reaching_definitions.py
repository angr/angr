# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.analysis import Analysis, register_analysis
from angr.calling_conventions import SimRegArg, default_cc
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType

from .s_rda_model import SRDAModel, populate_model
from .s_rda_view import SRDAView


class SReachingDefinitionsAnalysis(Analysis):
    """
    Constant and expression propagation that only supports SSA AIL graphs.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        subject,
        func_addr: int | None = None,
        func_graph: networkx.DiGraph[Block] | None = None,
        func_args: set[VirtualVariable] | None = None,
        use_callee_saved_regs_at_return: bool = False,
        track_tmps: bool = False,
        variable_map=None,
    ):
        if isinstance(subject, Block):
            self.block = subject
            self.func = None
            self.mode = "block"
        elif isinstance(subject, Function):
            self.block = None
            self.func = subject
            self.mode = "function"
        else:
            raise TypeError(f"Unsupported subject type {type(subject)}")

        self.func_graph = func_graph
        self.func_addr = func_addr if func_addr is not None else self.func.addr if self.func is not None else None
        self.func_args = func_args
        self._track_tmps = track_tmps
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return

        self._bp_as_gpr = False
        if self.func is not None:
            self._bp_as_gpr = self.func.info.get("bp_as_gpr", False)

        self.model = SRDAModel(
            func_graph,
            func_args,
            self.project.arch,
            platform=self.project.simos.name if self.project.simos is not None else None,
            language=self.project._languages[0] if self.project._languages else None,
            variable_map=variable_map,
            functions=self.project.kb.functions if self.project.kb is not None else None,
        )

        self._analyze()

    def _analyze(self):
        match self.mode:
            case "block":
                assert self.block is not None
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                assert self.func_graph is not None
                blocks = {(block.addr, block.idx): block for block in self.func_graph}
            case _:
                raise NotImplementedError

        populate_model(
            self.model,
            blocks,
            self.func_args,
            fix_undefined_vvars=self.mode == "function",
            track_tmps=self._track_tmps,
        )

        if self.mode == "function":
            assert self.func is not None

            srda_view = SRDAView(self.model)
            # the function entry block, used by observe()'s dominance-based fast path to build the dominator tree
            assert self.func_addr is not None
            entry_block = blocks.get((self.func_addr, None))

            # fix register uses at call sites

            # find all implicit vvar uses
            call_stmt_ids = []
            for block in blocks.values():
                for stmt_idx, stmt in enumerate(block.statements):
                    if (  # pylint:disable=too-many-boolean-expressions
                        (
                            isinstance(stmt, SideEffectStatement)
                            and isinstance(stmt.expr, Call)
                            and stmt.expr.args is None
                        )
                        or (isinstance(stmt, Assignment) and isinstance(stmt.src, Call) and stmt.src.args is None)
                        or (isinstance(stmt, Return) and stmt.ret_exprs and isinstance(stmt.ret_exprs[0], Call))
                    ):
                        call_stmt_ids.append(((block.addr, block.idx), stmt_idx))

            observations = srda_view.observe(
                [("stmt", insn_stmt_id, ObservationPointType.OP_BEFORE) for insn_stmt_id in call_stmt_ids],
                entry=entry_block,
            )
            for key, reg_to_vvarids in observations.items():
                _, ((block_addr, block_idx), stmt_idx), _ = key

                block = blocks[(block_addr, block_idx)]
                stmt = block.statements[stmt_idx]
                assert isinstance(stmt, (SideEffectStatement, Assignment, Return))

                call = (
                    stmt.expr
                    if isinstance(stmt, SideEffectStatement)
                    else stmt.src
                    if isinstance(stmt, Assignment)
                    else stmt.ret_exprs[0]
                )
                assert isinstance(call, Call)

                # conservatively add uses to all registers that are potentially used here
                call_cc = (
                    self.model.variable_map.calling_convention(call) if self.model.variable_map is not None else None
                )
                if call_cc is not None:
                    cc = call_cc
                else:
                    # just use all registers in the default calling convention because we don't know anything about
                    # the calling convention yet
                    cc_cls = default_cc(
                        self.project.arch.name,
                        platform=self.project.simos.name if self.project.simos is not None else None,
                    )
                    assert cc_cls is not None
                    cc = cc_cls(self.project.arch)

                codeloc = AILCodeLocation(block_addr, block_idx, stmt_idx, stmt.tags.get("ins_addr"))
                arg_locs = list(cc.ARG_REGS)
                if cc.FP_ARG_REGS:
                    arg_locs += [r_name for r_name in cc.FP_ARG_REGS if r_name not in arg_locs]

                for arg_reg_name in arg_locs:
                    reg_offset, reg_size = self.project.arch.registers[arg_reg_name]
                    if reg_offset in reg_to_vvarids:
                        for vvar_size in reg_to_vvarids[reg_offset]:
                            if vvar_size >= reg_size:
                                vvarid = reg_to_vvarids[reg_offset][vvar_size]
                                self.model.add_vvar_use(vvarid, None, codeloc)

            if self._use_callee_saved_regs_at_return:
                # handle callee-saved registers: add uses for these registers so that the restoration statements are not
                # considered dead assignments.
                cc = self.func.calling_convention
                if cc is None:
                    cc_cls = default_cc(
                        self.project.arch.name,
                        platform=self.project.simos.name if self.project.simos is not None else None,
                    )
                    assert cc_cls is not None
                    cc = cc_cls(self.project.arch)

                arch = self.project.arch
                ob_points = []
                endpoint_addrs = {end_point.addr for end_point in self.func.endpoints}
                for block in blocks.values():
                    if block.addr in endpoint_addrs:
                        ob_points.append(("node", (block.addr, block.idx), ObservationPointType.OP_AFTER))
                func_end_observations = srda_view.observe(ob_points, entry=entry_block)
                ignore_reg_offsets = {arch.sp_offset, arch.ip_offset}
                if not self._bp_as_gpr:
                    ignore_reg_offsets.add(arch.bp_offset)
                for key, reg_to_vvarids in func_end_observations.items():
                    _, (block_addr, block_idx), _ = key
                    block = blocks[(block_addr, block_idx)]
                    if not block.statements:
                        # totally unexpected
                        continue
                    stmt = block.statements[-1]
                    codeloc = AILCodeLocation(
                        block_addr, block_idx, len(block.statements) - 1, stmt.tags.get("ins_addr")
                    )
                    for reg in arch.register_list:
                        if (
                            reg.general_purpose
                            and reg.name not in cc.CALLER_SAVED_REGS
                            and reg.name not in cc.ARG_REGS
                            and reg.vex_offset not in ignore_reg_offsets
                            and (isinstance(cc.RETURN_VAL, SimRegArg) and reg.name != cc.RETURN_VAL.reg_name)
                        ):
                            reg_offset = self.project.arch.registers[reg.name][0]
                            if reg_offset in reg_to_vvarids:
                                max_vvar_size = max(reg_to_vvarids[reg_offset])
                                vvarid = reg_to_vvarids[reg_offset][max_vvar_size]
                                self.model.add_vvar_use(vvarid, None, codeloc)


register_analysis(SReachingDefinitionsAnalysis, "SReachingDefinitions")
