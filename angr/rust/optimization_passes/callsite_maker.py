from ailment.expression import BasePointerOffset, Const
from ailment.statement import Store, Call

from ..ailment.expression import Struct, Array
from ..definitions.structs import ArrayReference, Option
from ..sim_type import RustSimStruct
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...analyses.decompiler.structured_codegen.rust import unpack_typeref
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
                    ele.variable = base.variable
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

    def _condense_struct_instantiation(self, statements, ty):
        first_stmt = statements[0]
        fields = {stmt.offset: stmt.data for stmt in statements}
        condensed_fields = {}
        for offset in fields:
            field_ty = StructResolver(ty).find_field_type(offset)
            if isinstance(field_ty, ArrayReference) and offset + self.project.arch.bytes in fields:
                base = fields[offset]
                length = fields[offset + self.project.arch.bytes]
                elements = StructResolver(field_ty).resolve_element_ptrs(base, length)
                data = Array(base.idx, elements, field_ty)
                condensed_fields[offset] = data
            elif isinstance(field_ty, Option) and isinstance(fields[offset], Const):
                fields[offset].tags["type"] = field_ty.with_arch(self.project.arch)
                condensed_fields[offset] = fields[offset]
            else:
                condensed_fields[offset] = fields[offset]

        new_expr = Struct(first_stmt.data.idx, condensed_fields, ty)
        new_stmt = Store(
            first_stmt.idx,
            first_stmt.addr,
            new_expr,
            new_expr.size,
            self.project.arch.memory_endness,
            ins_addr=first_stmt.ins_addr,
        )
        new_stmt.variable = first_stmt.variable
        return [new_stmt]

    def _analyze(self, cache=None):
        # Fix struct instantiation
        for block in self._graph.nodes:
            statements = list(block.statements)
            new_statements = []
            while len(statements):
                stmt = statements.pop(0)
                if (
                    isinstance(stmt, Store)
                    and stmt.variable
                    and isinstance(stmt.variable, SimStackVariable)
                    and (
                        (ty := unpack_typeref(self.variable_manager.get_variable_type(stmt.variable)))
                        and isinstance(ty, RustSimStruct)
                    )
                ):
                    # It's probably a struct instantiation. Let's find all related statements!
                    statements.insert(0, stmt)
                    related_statements = []
                    while len(statements):
                        next_stmt = statements.pop(0)
                        if (
                            isinstance(next_stmt, Store)
                            and next_stmt.variable
                            and isinstance(next_stmt.variable, SimStackVariable)
                            and (ty.size // 8) > (offset := next_stmt.variable.offset - stmt.variable.offset) >= 0
                        ):
                            next_stmt.variable = stmt.variable
                            next_stmt.offset = offset
                            next_stmt.tags["struct_type"] = ty
                            related_statements.append(next_stmt)
                        else:
                            statements.insert(0, next_stmt)
                            break
                    new_statements.extend(self._condense_struct_instantiation(related_statements, ty))
                else:
                    new_statements.append(stmt)
            block.statements = new_statements
