from ailment.expression import BasePointerOffset, Const
from ailment.statement import Store

from ..definitions.structs import ArrayReference
from ..sim_type import RustSimStruct
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...sim_variable import SimStackVariable


class StructResolver:
    def __init__(self, struct_ty: RustSimStruct, arch=None):
        self.struct_ty = struct_ty
        self.arch = arch

    def find_field_type(self, offset):
        offsets = self.struct_ty.offsets
        for name, field_ty in self.struct_ty.fields.items():
            field_offset = offsets[name]
            if offset == field_offset:
                return field_ty
            elif isinstance(field_ty, RustSimStruct) and offsets[name] < offset < offsets[name] + field_ty.size // 8:
                return StructResolver(field_ty).find_field_type(offset - field_offset)
        return None

    def resolve_element_ptrs(self, base, length):
        result = []
        if isinstance(self.struct_ty, ArrayReference) and isinstance(length, Const) and isinstance(length.value, int):
            length = length.value
            if isinstance(base, Const) and isinstance(base.value, int):
                for i in range(length):
                    ele = base.copy()
                    ele.value += i * self.struct_ty.ele_ty.size // 8
                    result.append(ele)
            elif isinstance(base, BasePointerOffset):
                for i in range(length):
                    ele = base.copy()
                    ele.offset += i * self.struct_ty.ele_ty.size // 8
                    result.append(ele)
        return result


class CallsiteMaker(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
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
        self.variable_manager = self._variable_kb.variables[self._func.addr]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            if not block.statements:
                continue
            new_statements = []
            skip_one = False
            for i in range(len(block.statements) - 1):
                if skip_one:
                    skip_one = False
                    continue
                stmt = block.statements[i]
                next_stmt = block.statements[i + 1]
                if "struct_member_info" in stmt.tags:
                    offset, var, field_ty = stmt.struct_member_info
                    if (
                        isinstance(field_ty, ArrayReference)
                        and "struct_member_info" in next_stmt.tags
                        and isinstance(next_stmt, Store)
                        and next_stmt.variable
                        and stmt.variable
                        and isinstance(stmt.variable, SimStackVariable)
                        and isinstance(next_stmt.variable, SimStackVariable)
                        and next_stmt.variable.offset - stmt.variable.offset == self.project.arch.bytes
                    ):
                        elements = StructResolver(field_ty).resolve_element_ptrs(stmt.data, next_stmt.data)
                        stmt.tags["array_info"] = (elements, field_ty, next_stmt.data)
                        new_statements.append(stmt)
                        skip_one = True
                    else:
                        new_statements.append(stmt)
                else:
                    new_statements.append(stmt)
            new_statements.append(block.statements[-1])
            block.statements = new_statements
