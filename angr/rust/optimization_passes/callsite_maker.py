import ailment.expression
from ailment import Const
from ailment.expression import Convert, BasePointerOffset
from ailment.statement import Call, Store

from ..ailment.expression import Struct
from ..sim_type import RustSimStruct, RustSimTypeReference, RustSimTypeArray
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...knowledge_plugins.key_definitions import LiveDefinitions
from ...knowledge_plugins.key_definitions.constants import ObservationPointType


class StructResolver:
    def __init__(self, defs: LiveDefinitions, struct_ty: RustSimStruct):
        self.defs = defs
        self.struct_ty = struct_ty

    def _resolve(self, ty):
        if ty.__class__ in TypeHandlers:
            handler = TypeHandlers[ty.__class__]
            return handler(self, ty)
        return None

    def _resolve_reference(self, ty: RustSimTypeReference):
        if isinstance(ty.pts_to, RustSimTypeArray):
            pass

    def resolve_by_stack_offset(self, offset):
        fields = []
        for field in self.struct_ty.fields:
            print(field)


TypeHandlers = {RustSimTypeReference: StructResolver._resolve_reference}


class CallsiteMaker(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Make callsite based on known/recovered prototypes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.rd = self.project.analyses.ReachingDefinitions(
            subject=self._func,
            func_graph=self._graph,
            observe_all=True,
            element_limit=1,
        ).model
        self.codeloc_to_block = {}
        for block in self._graph.nodes:
            self.codeloc_to_block[(block.addr, block.idx)] = block
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_expr(self, expr):
        result = expr
        while isinstance(result, Convert):
            result = result.operand
        return result

    def _get_stmt_by_codeloc(self, codeloc):
        key = (codeloc.block_addr, codeloc.block_idx)
        if key in self.codeloc_to_block:
            return self.codeloc_to_block[key].statements[codeloc.stmt_idx]
        return None

    def _get_def_by_stack_offset(self, defs, offset, size):
        stack_defs = defs.get_stack_definitions(offset, size)
        if stack_defs:
            codeloc = next(iter(defs.get_stack_definitions(offset, size))).codeloc
            stmt = self._get_stmt_by_codeloc(codeloc)
            return self._extract_def_from_stmt(stmt)
        return None

    def _extract_def_from_stmt(self, stmt):
        if isinstance(stmt, Store):
            return stmt.data
        return None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
                    func = self.kb.functions[stmt.target.value]
                    if prototype := func.prototype:
                        defs = self.rd.get_observation_by_insn(stmt.ins_addr, ObservationPointType.OP_BEFORE)
                        for argty, arg in zip(prototype.args, stmt.args):
                            # Recover the definitions of struct arguments
                            if isinstance(argty, RustSimTypeReference) and isinstance(argty.pts_to, RustSimStruct):
                                arg = self._extract_expr(arg)
                                # If it's a stack pointer, recover the definitions of struct fields
                                if isinstance(arg, BasePointerOffset):
                                    # import ipdb
                                    #
                                    # ipdb.set_trace()
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset, arg.size)=}")
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset + 8, arg.size)=}")
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset + 16, arg.size)=}")
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset + 24, arg.size)=}")
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset + 32, arg.size)=}")
                                    print(f"{self._get_def_by_stack_offset(defs, arg.offset + 40, arg.size)=}")
                                    break
