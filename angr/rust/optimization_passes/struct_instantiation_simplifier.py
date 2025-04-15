from collections import defaultdict

import claripy
from ailment.expression import Const, VirtualVariable
from ailment.statement import Assignment
from archinfo import Endness

from .base import SSAVariableHelper
from ..mixins import CFAMixin, SRDAMixin, DFAMixin
from ..ailment.expression import Struct, Array
from ..definitions.structs import ArrayReference
from ..sim_type import RustSimStruct, RustSimTypeReference
from ..utils.ail_util import unwrap_stack_vvar_reference
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class StructBuilder:
    def __init__(self, context: "StructInstantiationSimplifier"):
        self.context = context
        self.pending_potential_structs = []
        self._arch = context.project.arch

    def _resolve_field(self, struct_ty, offset):
        offsets = struct_ty.offsets
        for name, field_ty in struct_ty.fields.items():
            field_offset = offsets[name]
            if offset == field_offset:
                return name, field_ty
            elif isinstance(field_ty, RustSimStruct) and offsets[name] < offset < offsets[name] + field_ty.size // 8:
                return self._resolve_field(field_ty, offset - field_offset)
        return None, None

    def _truncate(self, data, bits):
        if bits < data.bits and isinstance(data, Const):
            bv = claripy.BVV(data.value, data.bits)
            leftover = data.copy()
            data = data.copy()
            data.bits = bits
            leftover.bits = bv.size() - bits
            if self._arch.memory_endness == Endness.LE:
                data.value = bv[bits - 1 : 0].concrete_value
                leftover.value = bv[bv.size() - 1 : bits].concrete_value
            else:
                data.value = bv[bv.size() - 1 : bv.size() - bits].concrete_value
                leftover.value = bv[bv.size() - bits - 1 : 0].concrete_value
            return data, leftover
        return None, None

    def _fix_field_exprs(self, field_exprs, struct_ty):
        fixed_field_exprs = {}
        for offset in field_exprs:
            expr = field_exprs[offset]
            _, field_ty = self._resolve_field(struct_ty, offset)
            if field_ty and expr.size > field_ty.size // 8:
                new_expr, leftover = self._truncate(expr, field_ty.size)
                if new_expr is None:
                    return field_exprs
                fixed_field_exprs[offset] = new_expr
                fixed_field_exprs[offset + field_ty.size // 8] = leftover
            else:
                fixed_field_exprs[offset] = expr
        return fixed_field_exprs

    def _rebase_field_exprs(self, field_exprs, field_offset):
        rebased_field_exprs = {}
        for offset in field_exprs:
            if offset - field_offset >= 0:
                rebased_field_exprs[offset - field_offset] = field_exprs[offset]
        return rebased_field_exprs

    def _build_array(self, field_exprs, struct_ty) -> Array | None:
        ptr_offset = struct_ty.offsets["ptr"]
        len_offset = struct_ty.offsets["len"]
        if ptr_offset not in field_exprs or len_offset not in field_exprs:
            return None
        elements = []
        ptr_expr = field_exprs[ptr_offset]
        ele_ty = struct_ty.fields["ptr"].pts_to
        len_expr = field_exprs[len_offset]
        if isinstance(len_expr, Const):
            if isinstance(ptr_expr, Const):
                for i in range(len_expr.value):
                    ele_expr = ptr_expr.copy()
                    ele_expr.value = ptr_expr.value + ele_ty.size // 8 * i
                    ele_expr.tags["type"] = ele_ty
                    elements.append(ele_expr)
            elif vvar := unwrap_stack_vvar_reference(ptr_expr):
                for i in range(len_expr.value):
                    ele_expr = SSAVariableHelper(self.context).new_stack_vvar(vvar.stack_offset, ele_ty.size, vvar.tags)
                    # Looking for nested structs or struct references
                    if isinstance(ele_ty, RustSimTypeReference) and isinstance(ele_ty.pts_to, RustSimStruct):
                        self.pending_potential_structs.append((ele_expr, ele_ty.pts_to))
                    elif isinstance(ele_ty, RustSimStruct):
                        self.pending_potential_structs.append((ele_expr, ele_ty))
                    elements.append(ele_expr)
            else:
                return None
            return Array(0, elements, struct_ty)
        return None

    def build(self, field_exprs, struct_ty) -> Struct | Array | None:
        if field_exprs is None:
            return None
        field_exprs = self._fix_field_exprs(field_exprs, struct_ty)
        if isinstance(struct_ty, ArrayReference):
            # Special handling for ArrayReference type
            array = self._build_array(field_exprs, struct_ty)
            if array:
                return array
        fields = {}
        for field_name, field_ty in struct_ty.fields.items():
            field_offset = struct_ty.offsets[field_name]
            if isinstance(field_ty, RustSimStruct):
                field_struct = self.build(self._rebase_field_exprs(field_exprs, field_offset), field_ty)
                if field_struct is None:
                    return None
                fields[field_offset] = field_struct
            else:
                if field_offset in field_exprs:
                    fields[field_offset] = field_exprs[field_offset]
        return Struct(0, fields, struct_ty)


class StructInstantiationSimplifier(OptimizationPass, SRDAMixin, CFAMixin, DFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Make callsite based on known/recovered prototypes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self, self._graph)

        self._stmts_to_replace = defaultdict(list)
        self._stmts_to_remove = defaultdict(list)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _simplify_struct_instantiation(self, callsite_block, vvar: VirtualVariable, struct_ty: RustSimStruct):
        # If we can find all definitions of struct fields, let's create a struct instantiation
        # Otherwise just bind the offset and head variable to each field definition
        fields = {}
        stack_defs = self.collect_callsite_stack_defs(callsite_block)
        used_defs = []
        for offset, stack_def in stack_defs.items():
            offset = offset - vvar.stack_offset
            if 0 <= offset < struct_ty.size // self.project.arch.bytes:
                fields[offset] = stack_def.data
                used_defs.append(stack_def)

        builder = StructBuilder(self)
        struct = builder.build(fields, struct_ty)

        if struct and used_defs:
            first_stack_def = used_defs[0]
            new_vvar = SSAVariableHelper(self).new_stack_vvar(vvar.stack_offset, struct.bits, vvar.tags)
            new_stmt = Assignment(None, new_vvar, struct, **first_stack_def.stmt.tags)

            for expr, struct_ty in builder.pending_potential_structs:
                self._simplify_struct_instantiation(callsite_block, expr, struct_ty)

            self._stmts_to_replace[first_stack_def.block].append((first_stack_def.stmt_idx, new_stmt))
            for stack_def in used_defs[1:]:
                self._stmts_to_remove[stack_def.block].append(stack_def.stmt)

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            call = self.terminal_call(block)
            if (
                call
                and call.args
                and call.prototype
                and call.prototype.args
                and len(call.args) == len(call.prototype.args)
            ):
                for arg, arg_ty in zip(call.args, call.prototype.args):
                    if isinstance(arg_ty, RustSimTypeReference):
                        arg_ty = arg_ty.pts_to
                    if (vvar := unwrap_stack_vvar_reference(arg)) and isinstance(arg_ty, RustSimStruct):
                        self._simplify_struct_instantiation(block, vvar, arg_ty)

        for block in self._stmts_to_replace:
            for stmt_idx, replacement in self._stmts_to_replace[block]:
                block.statements[stmt_idx] = replacement

        for block in self._stmts_to_remove:
            for stmt in self._stmts_to_remove[block]:
                if stmt in block.statements:
                    block.statements.remove(stmt)
