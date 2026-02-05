from angr.ailment import Const, Register
from angr.ailment.expression import ComboRegister, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Call
from .utils import CallRewriter, replace_argument_pairs
from angr.rust.sim_type import RustSimTypeSlice
from angr.calling_conventions import SimStructArg, SimFunctionArgument, SimRegArg
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class SliceArgRewriter(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite slice arguments for Rust functions"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    @staticmethod
    def _flatten_locs(arg: SimFunctionArgument):
        if isinstance(arg, SimStructArg):
            locs = []
            for loc in arg.locs.values():
                locs += SliceArgRewriter._flatten_locs(loc)
            return locs
        return [arg]

    def _combine_vvars(self, vvar0: VirtualVariable, vvar1: VirtualVariable):
        if vvar0.was_reg and vvar1.was_reg:
            vvid = self.vvar_id_start
            self.vvar_id_start += 1
            return VirtualVariable(
                vvar0.idx,
                vvid,
                vvar0.bits + vvar1.bits,
                VirtualVariableCategory.COMBO_REGISTER,
                oident=(vvar0.oident, vvar1.oident),
                reg_vvars=[vvar0, vvar1],
                **vvar0.tags,
            )
        elif (
            vvar0.was_parameter
            and vvar1.was_parameter
            and vvar0.parameter_category == VirtualVariableCategory.REGISTER
            and vvar1.parameter_category == VirtualVariableCategory.REGISTER
        ):
            vvid = self.vvar_id_start
            self.vvar_id_start += 1
            # return VirtualVariable(
            #     vvar0.idx,
            #     vvid,
            #     vvar0.bits + vvar1.bits,
            #     VirtualVariableCategory.PARAMETER,
            #     oident=(VirtualVariableCategory.COMBO_REGISTER, (vvar0.oident[1], vvar1.oident[1])),
            #     reg_vvars=[vvar0, vvar1],
            #     **vvar0.tags,
            # )
        return None

    def _rewrite_slice_arguments(self, call: Call, block, stmt, is_expr):
        if isinstance(call.target, Const) and call.target.value in self.kb.functions:
            func = self.kb.functions[call.target.value]
            if (
                func.prototype
                and func.calling_convention
                and any(isinstance(arg_ty, RustSimTypeSlice) for arg_ty in func.prototype.args)
                and call.args
            ):
                offset_to_arg_ty = {}
                cur_offset = 0
                session = func.calling_convention.arg_session(func.prototype.returnty)
                for i, arg_ty in enumerate(func.prototype.args):
                    offset_to_arg_ty[cur_offset] = (arg_ty, func.calling_convention.next_arg(session, arg_ty))
                    cur_offset += arg_ty.size
                arg_to_offset = {}
                cur_offset = 0
                for arg in call.args:
                    arg_to_offset[arg] = cur_offset
                    cur_offset += arg.size * self.project.arch.byte_width

                if set(offset_to_arg_ty.keys()).issubset(set(arg_to_offset.values())):

                    def replace(arg0, arg1):
                        if isinstance(arg0, VirtualVariable) and isinstance(arg1, VirtualVariable):
                            arg0_offset = arg_to_offset[arg0]
                            arg_ty, arg_loc = offset_to_arg_ty[arg0_offset]
                            arg_locs = self._flatten_locs(arg_loc)
                            if (
                                isinstance(arg_ty, RustSimTypeSlice)
                                and isinstance(arg_loc, SimStructArg)
                                and len(arg_locs) == 2
                                and all(isinstance(arg, SimRegArg) for arg in arg_locs)
                            ):
                                combined_vvar = self._combine_vvars(arg0, arg1)
                                if combined_vvar is not None:
                                    return True, [combined_vvar]
                        return False, None

                    return replace_argument_pairs(call, replace)
        return call

    def _analyze(self, cache=None):
        rewriter = CallRewriter(self._rewrite_slice_arguments)
        for block in self._graph.nodes:
            rewriter.walk(block)

        self.out_graph = self._graph
