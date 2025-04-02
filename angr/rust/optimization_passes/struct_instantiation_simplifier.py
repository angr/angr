from collections import defaultdict

import claripy
from ailment.expression import BasePointerOffset, Const, VirtualVariable
from ailment.statement import Assignment
from archinfo import Endness

from .base import SSAVariableHelper
from ..mixins import StrMixin, CFAMixin, SRDAMixin, DFAMixin
from ..ailment.expression import Struct, Array
from ..definitions.structs import ArrayReference
from ..sim_type import RustSimStruct, RustSimTypeReference
from ..utils.ail_util import unwrap_stack_vvar_reference
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class StructResolver:
    def __init__(self, struct_ty: RustSimStruct, arch=None):
        self.struct_ty = struct_ty
        self.arch = arch

    def find_field(self, offset):
        offsets = self.struct_ty.offsets
        for name, field_ty in self.struct_ty.fields.items():
            field_offset = offsets[name]
            if offset == field_offset:
                return name, field_ty
            elif isinstance(field_ty, RustSimStruct) and offsets[name] < offset < offsets[name] + field_ty.size // 8:
                return StructResolver(field_ty).find_field(offset - field_offset)
        return None, None


class StructBuilder:
    def __init__(self, struct_ty: RustSimStruct, struct_members, context: "StructInstantiationSimplifier"):
        self.struct_ty = struct_ty
        self.struct_members = struct_members
        self.context = context

        self.pending_potential_structs = []

        self._arch = context.project.arch

        self._fix_struct_members()

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

    def _fix_struct_members(self):
        fixed_struct_members = {}
        for offset in self.struct_members:
            expr = self.struct_members[offset]
            _, field_ty = StructResolver(self.struct_ty, self._arch).find_field(offset)
            if field_ty and expr.size > field_ty.size // 8:
                new_expr, leftover = self._truncate(expr, field_ty.size)
                if new_expr is None:
                    self.struct_members = None
                    return
                fixed_struct_members[offset] = new_expr
                fixed_struct_members[offset + field_ty.size // 8] = leftover
            else:
                fixed_struct_members[offset] = expr
        self.struct_members = fixed_struct_members

    def _rebased_struct_members(self, field_offset):
        rebased_struct_members = {}
        for offset in self.struct_members:
            if offset - field_offset >= 0:
                rebased_struct_members[offset - field_offset] = self.struct_members[offset]
        return rebased_struct_members

    def _build_for_array(self) -> Array | None:
        ptr_offset = self.struct_ty.offsets["ptr"]
        len_offset = self.struct_ty.offsets["len"]
        if ptr_offset not in self.struct_members or len_offset not in self.struct_members:
            return None
        elements = []
        ptr_expr = self.struct_members[ptr_offset]
        ele_ty = self.struct_ty.fields["ptr"].pts_to
        len_expr = self.struct_members[len_offset]
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
            return Array(0, elements, self.struct_ty)
        return None

    def build(self) -> Struct | Array | None:
        if self.struct_members is None:
            return None
        if isinstance(self.struct_ty, ArrayReference):
            # Special handling for ArrayReference type
            array = self._build_for_array()
            if array:
                return array
        fields = {}
        for field_name, field_ty in self.struct_ty.fields.items():
            field_offset = self.struct_ty.offsets[field_name]
            if isinstance(field_ty, RustSimStruct):
                builder = StructBuilder(field_ty, self._rebased_struct_members(field_offset), self.context)
                field_struct = builder.build()
                self.pending_potential_structs += builder.pending_potential_structs
                if field_struct is None:
                    return None
                fields[field_offset] = field_struct
            elif isinstance(field_ty, ArrayReference):
                pass
            else:
                if field_offset in self.struct_members:
                    fields[field_offset] = self.struct_members[field_offset]
        return Struct(0, fields, self.struct_ty)


class StructInstantiationSimplifier(
    OptimizationPass,
    SRDAMixin,
    CFAMixin,
    StrMixin,
    DFAMixin,
):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Make callsite based on known/recovered prototypes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFAMixin.__init__(self, self._graph, self.project)

        self.codeloc_to_block = {}
        for node in self._graph.nodes:
            self.codeloc_to_block[(node.addr, node.idx)] = node

        self._stmts_to_replace = defaultdict(list)
        self._stmts_to_remove = defaultdict(list)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _simplify_struct_instantiation(self, block, vvar: VirtualVariable, struct_ty: RustSimStruct):
        # If we can find all definitions of struct fields, let's create a struct instantiation
        # Otherwise just bind the offset and head variable to each field definition
        fields = {}
        offset_to_stmt = {}
        for idx, stmt in enumerate(block.statements):
            dst_vvar, src_data = self.extract_write_to_stack_vvar(stmt)
            if dst_vvar and src_data:
                offset = dst_vvar.stack_offset - vvar.stack_offset
                if 0 <= offset < struct_ty.size // 8:
                    fields[offset] = src_data
                    offset_to_stmt[offset] = (idx, stmt)

        builder = StructBuilder(struct_ty, fields, self)
        struct = builder.build()

        if struct and offset_to_stmt:
            used_stmts = sorted(offset_to_stmt.values(), key=lambda ele: ele[0])
            head_stmt = used_stmts[0][1]
            new_vvar = SSAVariableHelper(self).new_stack_vvar(vvar.stack_offset, struct.bits, vvar.tags)
            new_stmt = Assignment(None, new_vvar, struct, **head_stmt.tags)

            for expr, struct_ty in builder.pending_potential_structs:
                self._simplify_struct_instantiation(block, expr, struct_ty)

            self._stmts_to_replace[block].append((used_stmts[0][0], new_stmt))
            for _, stmt in used_stmts[1:]:
                self._stmts_to_remove[block].append(stmt)

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
