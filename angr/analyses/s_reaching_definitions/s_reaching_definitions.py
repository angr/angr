from __future__ import annotations

from angr.ailment.block import Block
from angr.ailment.statement import Assignment, Call, Return
from angr.ailment.expression import VirtualVariable
import networkx

from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import get_vvar_uselocs, get_vvar_deflocs, get_tmp_deflocs, get_tmp_uselocs
from angr.calling_conventions import default_cc
from .s_rda_model import SRDAModel
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
        track_tmps: bool = False,
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

        self._bp_as_gpr = False
        if self.func is not None:
            self._bp_as_gpr = self.func.info.get("bp_as_gpr", False)

        self.model = SRDAModel(func_graph, func_args, self.project.arch)

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

        phi_vvars: dict[int, set[int]] = {}
        # find all vvar definitions
        vvar_deflocs = get_vvar_deflocs(blocks.values(), phi_vvars=phi_vvars)
        # find all explicit vvar uses
        vvar_uselocs = get_vvar_uselocs(blocks.values())

        # update vvar definitions using function arguments
        if self.func_args:
            for vvar in self.func_args:
                if vvar.varid not in vvar_deflocs:
                    vvar_deflocs[vvar.varid] = vvar, ExternalCodeLocation()
            self.model.func_args = self.func_args

        # update model
        for vvar_id, (vvar, defloc) in vvar_deflocs.items():
            self.model.varid_to_vvar[vvar_id] = vvar
            self.model.all_vvar_definitions[vvar_id] = defloc
            if vvar_id in vvar_uselocs:
                for useloc in vvar_uselocs[vvar_id]:
                    self.model.add_vvar_use(vvar_id, *useloc)

        self.model.phi_vvar_ids = set(phi_vvars)
        self.model.phivarid_to_varids = {}
        for vvar_id, src_vvars in phi_vvars.items():
            self.model.phivarid_to_varids[vvar_id] = src_vvars

        if self.mode == "function":

            # fix register definitions for arguments
            defined_vvarids = set(vvar_deflocs)
            undefined_vvarids = set(vvar_uselocs.keys()).difference(defined_vvarids)
            for vvar_id in undefined_vvarids:
                used_vvar = next(iter(vvar_uselocs[vvar_id]))[0]
                self.model.varid_to_vvar[vvar_id] = used_vvar
                self.model.all_vvar_definitions[vvar_id] = ExternalCodeLocation()
                if vvar_id in vvar_uselocs:
                    for vvar_useloc in vvar_uselocs[vvar_id]:
                        self.model.add_vvar_use(vvar_id, *vvar_useloc)

            srda_view = SRDAView(self.model)

            # fix register uses at call sites

            # find all implicit vvar uses
            call_stmt_ids = []
            for block in blocks.values():
                for stmt_idx, stmt in enumerate(block.statements):
                    if (  # pylint:disable=too-many-boolean-expressions
                        (isinstance(stmt, Call) and stmt.args is None)
                        or (isinstance(stmt, Assignment) and isinstance(stmt.src, Call) and stmt.src.args is None)
                        or (isinstance(stmt, Return) and stmt.ret_exprs and isinstance(stmt.ret_exprs[0], Call))
                    ):
                        call_stmt_ids.append(((block.addr, block.idx), stmt_idx))

            observations = srda_view.observe(
                [("stmt", insn_stmt_id, ObservationPointType.OP_BEFORE) for insn_stmt_id in call_stmt_ids]
            )
            for key, reg_to_vvarids in observations.items():
                _, ((block_addr, block_idx), stmt_idx), _ = key

                block = blocks[(block_addr, block_idx)]
                stmt = block.statements[stmt_idx]
                assert isinstance(stmt, (Call, Assignment, Return))

                call = (
                    stmt if isinstance(stmt, Call) else stmt.src if isinstance(stmt, Assignment) else stmt.ret_exprs[0]
                )
                assert isinstance(call, Call)

                # conservatively add uses to all registers that are potentially used here
                if call.calling_convention is not None:
                    cc = call.calling_convention
                else:
                    # just use all registers in the default calling convention because we don't know anything about
                    # the calling convention yet
                    cc_cls = default_cc(self.project.arch.name)
                    assert cc_cls is not None
                    cc = cc_cls(self.project.arch)

                codeloc = CodeLocation(block_addr, stmt_idx, block_idx=block_idx, ins_addr=stmt.ins_addr)
                arg_locs = list(cc.ARG_REGS)
                if cc.FP_ARG_REGS:
                    arg_locs += [r_name for r_name in cc.FP_ARG_REGS if r_name not in arg_locs]

                for arg_reg_name in arg_locs:
                    reg_offset = self.project.arch.registers[arg_reg_name][0]
                    if reg_offset in reg_to_vvarids:
                        vvarid = reg_to_vvarids[reg_offset]
                        self.model.add_vvar_use(vvarid, None, codeloc)

        if self._track_tmps:
            # track tmps
            tmp_deflocs = get_tmp_deflocs(blocks.values())
            # find all vvar uses
            tmp_uselocs = get_tmp_uselocs(blocks.values())

            # update model
            for block_loc, d in tmp_deflocs.items():
                for tmp_atom, stmt_idx in d.items():
                    self.model.all_tmp_definitions[block_loc][tmp_atom] = stmt_idx

                    if tmp_atom in tmp_uselocs[block_loc]:
                        for tmp_at_use, use_stmt_idx in tmp_uselocs[block_loc][tmp_atom]:
                            if tmp_atom not in self.model.all_tmp_uses[block_loc]:
                                self.model.all_tmp_uses[block_loc][tmp_atom] = set()
                            self.model.all_tmp_uses[block_loc][tmp_atom].add((tmp_at_use, use_stmt_idx))


register_analysis(SReachingDefinitionsAnalysis, "SReachingDefinitions")
