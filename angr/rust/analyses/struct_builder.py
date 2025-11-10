from collections import OrderedDict

import claripy
from archinfo import Endness

from angr.analyses import Analysis, AnalysesHub
from angr.ailment import UnaryOp
from angr.ailment.expression import Const, Struct, Array, Load
from angr.rust.sim_type import RustSimStruct, RustSimTypeReference, RustSimTypeArrayRef
from angr.rust.utils.ail import unwrap_stack_vvar_reference


class StructBuilder(Analysis):
    def __init__(self, context, strict=False):
        self.context = context
        self.pending_potential_structs = []
        self.strict = strict

    def _resolve_field(self, struct_ty, offset):
        offsets = struct_ty.offsets
        for name, field_ty in struct_ty.fields.items():
            field_offset = offsets[name]
            if offset == field_offset and field_ty.size > 0:
                return name, field_ty
            elif isinstance(field_ty, RustSimStruct) and offsets[name] < offset < offsets[name] + field_ty.size // 8:
                return self._resolve_field(field_ty, offset - field_offset)
        return None, None

    def _truncate(self, data, bits):
        if bits < data.bits:
            if isinstance(data, Const):
                bv = claripy.BVV(data.value, data.bits)
                leftover = data.copy()
                data = data.copy()
                data.bits = bits
                leftover.bits = bv.size() - bits
                if self.project.arch.memory_endness == Endness.LE:
                    data.value = bv[bits - 1 : 0].concrete_value
                    leftover.value = bv[bv.size() - 1 : bits].concrete_value
                else:
                    data.value = bv[bv.size() - 1 : bv.size() - bits].concrete_value
                    leftover.value = bv[bv.size() - bits - 1 : 0].concrete_value
                return data, leftover
            elif isinstance(data, Load) and isinstance(data.addr, UnaryOp) and data.addr.op == "Reference":
                size = bits // self.project.arch.byte_width
                leftover_size = (data.bits - bits) // self.project.arch.byte_width
                leftover = data.copy()
                leftover.addr = data.addr + Const(None, None, size, data.addr.bits)
                leftover.size = leftover_size
                data = data.copy()
                data.size = size
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
        ptr_offset = struct_ty.offsets.get("ptr", None)
        len_offset = struct_ty.offsets.get("len", None)
        if ptr_offset is None or len_offset is None or ptr_offset not in field_exprs or len_offset not in field_exprs:
            return None
        elements = []
        ptr_expr = field_exprs[ptr_offset]
        ele_ty = struct_ty.fields["ptr"].pts_to
        len_expr = field_exprs[len_offset]
        if isinstance(len_expr, Const):
            if len_expr.value > 64:
                # That's insane
                return None
            if isinstance(ptr_expr, Const):
                for i in range(len_expr.value):
                    ele_expr = ptr_expr.copy()
                    ele_expr.value = ptr_expr.value + ele_ty.size // 8 * i
                    ele_expr.tags["type"] = ele_ty
                    elements.append(ele_expr)
            elif vvar := unwrap_stack_vvar_reference(ptr_expr):
                for i in range(len_expr.value):
                    ele_expr = self.context.new_stack_vvar(
                        vvar.stack_offset + i * (ele_ty.size // 8), ele_ty.size, vvar.tags, record=False
                    )
                    # Looking for nested structs or struct references
                    if isinstance(ele_ty, RustSimTypeReference) and isinstance(ele_ty.pts_to, RustSimStruct):
                        self.pending_potential_structs.append((ele_expr, ele_ty.pts_to))
                    elif isinstance(ele_ty, RustSimStruct):
                        self.pending_potential_structs.append((ele_expr, ele_ty))
                    elements.append(ele_expr)
            else:
                return None
            return Array(0, elements, struct_ty.size)
        return None

    def build(self, field_exprs, struct_ty) -> Struct | Array | None:
        if field_exprs is None:
            return None
        field_exprs = self._fix_field_exprs(field_exprs, struct_ty)
        if isinstance(struct_ty, RustSimTypeArrayRef):
            # Special handling for ArrayReference type
            array = self._build_array(field_exprs, struct_ty)
            if array:
                return array
            elif self.strict:
                return None
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
                elif self.strict:
                    return None
        fields = OrderedDict(sorted(fields.items(), key=lambda t: t[0]))
        return Struct(0, struct_ty.name, fields, struct_ty.offsets, struct_ty.size)


AnalysesHub.register_default("StructBuilder", StructBuilder)
