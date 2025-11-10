from collections import defaultdict, OrderedDict

import claripy
from archinfo import Endness

from angr.rust.optimization_passes.utils import CallReplacer
from angr.ailment import UnaryOp
from angr.ailment.expression import Const, VirtualVariable, Struct, Array, Load, BinaryOp
from angr.ailment.statement import Assignment, Call
from angr.rust.mixins import CFAMixin, SRDAMixin, DFAMixin, SSAVariableMixin
from angr.rust.sim_type import RustSimStruct, RustSimTypeReference, RustSimTypeArrayRef, RustSimTypeUnit, RustSimTypeInt
from angr.rust.utils.ail import unwrap_stack_vvar_reference
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.utils.ssa import VVarUsesCollector


class StructBuilder:
    def __init__(self, context: "StructInstantiationSimplifier"):
        self.context = context
        self.pending_potential_structs = []
        self._arch = context.project.arch

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
                if self._arch.memory_endness == Endness.LE:
                    data.value = bv[bits - 1 : 0].concrete_value
                    leftover.value = bv[bv.size() - 1 : bits].concrete_value
                else:
                    data.value = bv[bv.size() - 1 : bv.size() - bits].concrete_value
                    leftover.value = bv[bv.size() - bits - 1 : 0].concrete_value
                return data, leftover
            elif isinstance(data, Load) and isinstance(data.addr, UnaryOp) and data.addr.op == "Reference":
                size = bits // self.context.project.arch.byte_width
                leftover_size = (data.bits - bits) // self.context.project.arch.byte_width
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
        fields = OrderedDict(sorted(fields.items(), key=lambda t: t[0]))
        return Struct(0, struct_ty.name, fields, struct_ty.offsets, struct_ty.size)


class StructInstantiationSimplifier(OptimizationPass, SRDAMixin, CFAMixin, DFAMixin, SSAVariableMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Make callsite based on known/recovered prototypes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self, self._graph)
        SSAVariableMixin.__init__(self, self)

        self._stmts_to_replace = defaultdict(list)
        self._stmts_to_remove = defaultdict(list)

        collector = VVarUsesCollector()
        for block in self._graph.nodes:
            collector.walk(block)
        self._vvar_uses = collector.vvar_and_uselocs

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _expand_fields(self, struct: Struct):
        expanded_fields = []
        for field in struct.fields.values():
            if isinstance(field, Struct):
                expanded_fields += self._expand_fields(field)
            else:
                expanded_fields.append(field)
        return expanded_fields

    def _convert_to_stack_vvar(self, struct: Struct | Array):
        if isinstance(struct, Array):
            return None
        src_offset = None
        expected_offset = None
        expanded_fields = self._expand_fields(struct)
        for field in expanded_fields:
            if isinstance(field, Load) and (
                (vvar := unwrap_stack_vvar_reference(field.addr))
                and isinstance(vvar, VirtualVariable)
                and vvar.was_stack
                and (expected_offset is None or vvar.stack_offset == expected_offset)
            ):
                if src_offset is None:
                    src_offset = vvar.stack_offset
                expected_offset = vvar.stack_offset + field.size
            elif (
                isinstance(field, Load)
                and isinstance(field.addr, BinaryOp)
                and field.addr.op == "Add"
                and (
                    (vvar := unwrap_stack_vvar_reference(field.addr.operands[0]))
                    and isinstance(vvar, VirtualVariable)
                    and vvar.was_stack
                    and isinstance(field.addr.operands[1], Const)
                    and (expected_offset is None or vvar.stack_offset + field.addr.operands[1].value == expected_offset)
                )
            ):
                offset = vvar.stack_offset + field.addr.operands[1].value
                if src_offset is None:
                    src_offset = offset
                expected_offset = offset + field.size
            elif (
                isinstance(field, VirtualVariable)
                and field.was_stack
                and (expected_offset is None or field.stack_offset == expected_offset)
            ):
                if src_offset is None:
                    src_offset = field.stack_offset
                expected_offset = field.stack_offset + field.size
            else:
                return None
        if src_offset is not None:
            return self.new_stack_vvar(src_offset, struct.bits, {})
        return None

    def _simplify_callsite_struct_instantiation(self, callsite_block, vvar: VirtualVariable, struct_ty: RustSimStruct):
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
            if len(used_defs) > 1:
                first_stack_def = used_defs[0]
                new_vvar = self.new_stack_vvar(vvar.stack_offset, struct.bits, vvar.tags)
                src = self._convert_to_stack_vvar(struct) or struct
                src.tags["type"] = struct_ty
                new_stmt = Assignment(None, new_vvar, src, **first_stack_def.stmt.tags)

                # Collect type hints
                self.project.kb.type_hints.add_type_hint(new_vvar, struct_ty)

                for expr, struct_ty in builder.pending_potential_structs:
                    self._simplify_callsite_struct_instantiation(callsite_block, expr, struct_ty)

                self._stmts_to_replace[first_stack_def.block].append((first_stack_def.stmt_idx, new_stmt))
                for stack_def in used_defs[1:]:
                    self._stmts_to_remove[stack_def.block].append(stack_def.stmt)
            else:
                # Collect type hints
                self.project.kb.type_hints.add_type_hint(vvar, struct_ty)

    def _build_struct_ty(self, fields):
        if not fields:
            return RustSimTypeUnit().with_arch(self.project.arch)
        ty_fields = {}
        for offset in sorted(fields.keys()):
            expr = fields[offset]
            arg_ty = RustSimTypeInt(expr.bits, signed=False)
            cur_size = RustSimStruct(ty_fields).with_arch(self.project.arch).size // self.project.arch.bytes
            if cur_size < offset:
                ty_fields[f"padding_{cur_size}"] = RustSimTypeInt(offset - cur_size, signed=False)
            ty_fields[f"field_{offset}"] = arg_ty
        struct_ty = RustSimStruct(ty_fields).with_arch(self.project.arch)
        struct_ty.name = f"struct{struct_ty.size // 8}"
        return struct_ty.with_arch(self.project.arch)

    def _try_build_struct_instantiation(self, sorted_stmts):
        if len(sorted_stmts) >= 2:
            if self._vvar_uses[sorted_stmts[0].dst.varid] and not any(
                self._vvar_uses[stmt.dst.varid] for stmt in sorted_stmts[1:]
            ):
                expected_offset = None
                fields = {}
                for stmt in sorted_stmts:
                    if (
                        expected_offset is None
                        or self.project.arch.bytes >= stmt.dst.stack_offset - expected_offset >= 0
                    ):
                        expected_offset = stmt.dst.stack_offset + stmt.src.size
                        field_offset = stmt.dst.stack_offset - sorted_stmts[0].dst.stack_offset
                        fields[field_offset] = stmt.src
                    else:
                        return None, None
                struct_ty = self._build_struct_ty(fields)
                struct = Struct(None, struct_ty.name, fields, struct_ty.offsets, struct_ty.size)
                return struct_ty, struct
        return None, None

    @staticmethod
    def _group_consecutive_stmts(stack_defs):
        groups = []
        current_group = []
        last_idx = None

        for offset, stack_def in stack_defs.items():
            stmt_idx = stack_def.stmt_idx

            if last_idx is None or stmt_idx == last_idx + 1:
                current_group.append(stack_def.stmt)
            else:
                if current_group:
                    groups.append(current_group)
                current_group = [stack_def.stmt]

            last_idx = stmt_idx

        if current_group:
            groups.append(current_group)

        return groups

    def _simplify_struct_instantiation(self, block):
        stack_defs = self.collect_stack_defs_at(block)
        consecutive_stmts_groups = self._group_consecutive_stmts(stack_defs)
        for stmts in consecutive_stmts_groups:
            if all(isinstance(stmt, Assignment) and stmt not in self._stmts_to_remove[block] for stmt in stmts):
                sorted_stmts = sorted(stmts, key=lambda stmt: stmt.dst.stack_offset)
                struct_ty, struct = self._try_build_struct_instantiation(sorted_stmts)
                if struct:
                    vvar = sorted_stmts[0].dst
                    new_vvar = self.new_stack_vvar(vvar.stack_offset, struct.bits, vvar.tags)
                    src = self._convert_to_stack_vvar(struct) or struct
                    new_stmt = Assignment(None, new_vvar, src, **sorted_stmts[0].tags)

                    # Collect type hints
                    self.project.kb.type_hints.add_type_hint(new_vvar, struct_ty)

                    self._stmts_to_replace[block].append((block.statements.index(sorted_stmts[0]), new_stmt))
                    for stmt in sorted_stmts[1:]:
                        self._stmts_to_remove[block].append(stmt)

    def _align_prototype_and_args(self):
        def callback(expr: Call, block, stmt, is_expr):
            args = list(expr.args)
            prototype = expr.prototype
            if prototype and len(args) > len(prototype.args):
                new_args = []
                changed = False
                offset_to_arg_ty = {}
                cur_offset = 0
                for arg_ty in prototype.args:
                    offset_to_arg_ty[cur_offset] = arg_ty
                    cur_offset += arg_ty.size // self.project.arch.bytes
                cur_offset = 0
                while args:
                    arg = args.pop(0)
                    if cur_offset in offset_to_arg_ty:
                        expected_arg_ty = offset_to_arg_ty[cur_offset]
                        if isinstance(expected_arg_ty, RustSimTypeArrayRef) and len(args) > 0:
                            next_arg = args.pop(0)
                            array = StructBuilder(self).build({0: arg, arg.size: next_arg}, expected_arg_ty)
                            if array is not None:
                                changed = True
                                new_args.append(array)
                                cur_offset += arg.size + next_arg.size
                            else:
                                new_args.append(arg)
                                args.append(next_arg)
                                cur_offset += arg.size
                        else:
                            new_args.append(arg)
                            cur_offset += arg.size
                    else:
                        new_args.append(arg)
                        cur_offset += arg.size
                if changed:
                    expr = expr.copy()
                    expr.args = new_args
                    return expr
            return None

        walker = CallReplacer(callback)
        for block in self._graph.nodes:
            walker.walk(block)

    def _analyze(self, cache=None):
        # First, align callsite arguments with known/recovered prototypes
        self._align_prototype_and_args()

        for block in self._graph.nodes:
            # Recover structs by function calls
            call = self.terminal_call(block)
            if call and call.args and call.prototype and call.prototype.args:
                if len(call.args) == len(call.prototype.args):
                    for arg, arg_ty in zip(call.args, call.prototype.args):
                        if isinstance(arg_ty, RustSimTypeReference):
                            arg_ty = arg_ty.pts_to
                        if (vvar := unwrap_stack_vvar_reference(arg)) and isinstance(arg_ty, RustSimStruct):
                            self._simplify_callsite_struct_instantiation(block, vvar, arg_ty)
                        if (
                            isinstance(arg_ty, RustSimTypeArrayRef)
                            and isinstance(arg_ty.ele_ty, RustSimStruct)
                            and isinstance(arg, Array)
                        ):
                            for element in arg.elements:
                                if isinstance(element, VirtualVariable):
                                    self._simplify_callsite_struct_instantiation(block, element, arg_ty.ele_ty)

                elif len(call.args) > len(call.prototype.args):
                    # Handle possible struct flattening
                    offset_to_arg = {}
                    offset_to_arg_ty = {}
                    cur_offset = 0
                    for arg in call.args:
                        offset_to_arg[cur_offset] = arg
                        cur_offset += arg.size
                    cur_offset = 0
                    for arg_ty in call.prototype.args:
                        offset_to_arg_ty[cur_offset] = arg_ty
                        cur_offset += arg_ty.size // 8
                    for offset in set(offset_to_arg) & set(offset_to_arg_ty):
                        arg = offset_to_arg[offset]
                        arg_ty = offset_to_arg_ty[offset]
                        if arg.size == arg_ty.size // self.project.arch.bytes:
                            if isinstance(arg_ty, RustSimTypeReference):
                                arg_ty = arg_ty.pts_to
                            if (vvar := unwrap_stack_vvar_reference(arg)) and isinstance(arg_ty, RustSimStruct):
                                self._simplify_callsite_struct_instantiation(block, vvar, arg_ty)

            # Recover other structs
            self._simplify_struct_instantiation(block)

        for block in self._stmts_to_replace:
            for stmt_idx, replacement in self._stmts_to_replace[block]:
                block.statements[stmt_idx] = replacement

        for block in self._stmts_to_remove:
            for stmt in self._stmts_to_remove[block]:
                if stmt in block.statements:
                    block.statements.remove(stmt)

        self.fix_stack_vvar_uses()
        self.out_graph = self._graph
