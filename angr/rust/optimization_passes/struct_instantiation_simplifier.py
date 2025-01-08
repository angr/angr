from collections import defaultdict

import claripy
from ailment.expression import BasePointerOffset, Const, VirtualVariable
from ailment.statement import Store, Assignment, Call
from archinfo import Endness

from ..mixins.str_mixin import StrMixin
from ..mixins.cfa_mixin import CFAMixin
from ..mixins.srda_mixin import SRDAMixin
from ..ailment.expression import Struct, Array
from ..definitions.structs import ArrayReference, Arguments
from ..sim_type import RustSimStruct, RustSimTypeReference
from ..utils.ail_util import get_terminal_call
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...analyses.s_reaching_definitions import SRDAView
from ...code_location import CodeLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE


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

    def _build_for_array(self, block, stmt) -> Array | None:
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
            elif isinstance(ptr_expr, BasePointerOffset):
                for i in range(len_expr.value):
                    ele_expr = ptr_expr.copy()
                    ele_expr.offset += ele_ty.size // 8 * i
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

    def build(self, block, stmt) -> Struct | Array | None:
        if self.struct_members is None:
            return None
        if isinstance(self.struct_ty, ArrayReference):
            # Special handling for ArrayReference type
            array = self._build_for_array(block, stmt)
            if array:
                return array
        fields = {}
        for field_name, field_ty in self.struct_ty.fields.items():
            field_offset = self.struct_ty.offsets[field_name]
            if isinstance(field_ty, RustSimStruct):
                builder = StructBuilder(field_ty, self._rebased_struct_members(field_offset), self.context)
                field_struct = builder.build(block, stmt)
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


class StructInstantiationSimplifier(OptimizationPass, SRDAMixin, CFAMixin, StrMixin):
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

    def _get_stmt_by_codeloc(self, codeloc: CodeLocation):
        block = self._get_block_by_codeloc(codeloc)
        if block and len(block.statements) > codeloc.stmt_idx:
            return block.statements[codeloc.stmt_idx]
        return None

    def _get_block_by_codeloc(self, codeloc: CodeLocation):
        return self.codeloc_to_block.get((codeloc.block_addr, codeloc.block_idx), None)

    def _is_consecutive_codelocs(self, codelocs):
        if len({(codeloc.block_addr, codeloc.block_idx) for codeloc in codelocs}) != 1:
            return False
        stmt_idxes = sorted([codeloc.stmt_idx for codeloc in codelocs])
        return stmt_idxes[-1] - stmt_idxes[0] + 1 == len(stmt_idxes)

    def _match_existing_type(self, struct_ty: RustSimStruct, collected_members):
        arch_bytes = self.project.arch.bytes
        # Match with Arguments
        arguments_ty = Arguments.with_arch(self.project.arch)
        pieces_ptr_offset = 0
        pieces_len_offset = arch_bytes
        args_ptr_offset = 2 * arch_bytes
        args_len_offset = 3 * arch_bytes
        if (
            struct_ty.size == arguments_ty.size
            and pieces_ptr_offset in collected_members
            and pieces_len_offset in collected_members
            and args_ptr_offset in collected_members
            and args_len_offset in collected_members
            and isinstance(collected_members[pieces_ptr_offset], Const)
            and isinstance(collected_members[pieces_len_offset], Const)
            and isinstance(collected_members[args_len_offset], Const)
            and 1 >= collected_members[pieces_len_offset].value - collected_members[args_len_offset].value >= 0
            and self.extract_str_from_addr(collected_members[pieces_ptr_offset].value, infer_empty_str=True) is not None
        ):
            return arguments_ty
        return struct_ty

    def _simplify_struct_instantiation(
        self, block, last_stmt, expr: BasePointerOffset | VirtualVariable, struct_ty: RustSimStruct
    ):
        # if self.match_call(block, "core::iter::adapters::try_process"):
        #     import ipdb
        #
        #     ipdb.set_trace()
        assert isinstance(expr, BasePointerOffset) or (isinstance(expr, VirtualVariable) and expr.was_stack)
        expr_offset = expr.offset if isinstance(expr, BasePointerOffset) else expr.stack_offset
        # If we can find all definitions of struct fields, let's create a struct instantiation
        # Otherwise just bind the offset and head variable to each field definition
        collected_members = {}
        offset = expr_offset
        offset_to_codeloc = {}
        while offset - expr_offset < struct_ty.size // 8:
            # Workaround: In case the Store statement is not ssailified
            value = None
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Store) and isinstance(stmt.addr, BasePointerOffset) and stmt.addr.offset == offset:
                    codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                    offset_to_codeloc[offset - expr_offset] = codeloc
                    value = stmt.data
            if not value:
                vvar = self.get_stack_vvar_by_insn(offset, last_stmt.ins_addr, block.idx)
                def_ = self.get_def_by_vvar(vvar) if vvar else None
                if vvar and def_:
                    value = self.get_vvar_value(vvar)
                    if isinstance(value, Call):
                        value = vvar
                    else:
                        codeloc = def_.codeloc
                        offset_to_codeloc[offset - expr_offset] = codeloc
            if value:
                collected_members[offset - expr_offset] = value
                offset += value.size
            else:
                offset += 1

        struct_ty = self._match_existing_type(struct_ty, collected_members)
        builder = StructBuilder(struct_ty, collected_members, self)
        struct = builder.build(block, last_stmt)

        # if struct and 0 in offset_to_codeloc and self._is_consecutive_codelocs(offset_to_codeloc.values()):
        if struct and 0 in offset_to_codeloc:
            codeloc = offset_to_codeloc[0]
            head_stmt = self._get_stmt_by_codeloc(codeloc)
            store = Store(
                idx=head_stmt.idx,
                addr=expr,
                data=struct,
                size=struct.size,
                endness=self.project.arch.memory_endness,
                **head_stmt.tags,
            )

            for expr, struct_ty in builder.pending_potential_structs:
                self._simplify_struct_instantiation(block, last_stmt, expr, struct_ty)

            for offset, codeloc in offset_to_codeloc.items():
                block = self._get_block_by_codeloc(codeloc)
                stmt = self._get_stmt_by_codeloc(codeloc)
                if stmt in block.statements:
                    if offset == 0:
                        self._stmts_to_replace[block].append((codeloc.stmt_idx, store))
                    else:
                        self._stmts_to_remove[block].append(stmt)

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            call = get_terminal_call(block)
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
                    if isinstance(arg, BasePointerOffset) and isinstance(arg_ty, RustSimStruct):
                        self._simplify_struct_instantiation(block, block.statements[-1], arg, arg_ty)

        for block in self._stmts_to_replace:
            for stmt_idx, replacement in self._stmts_to_replace[block]:
                block.statements[stmt_idx] = replacement

        for block in self._stmts_to_remove:
            for stmt in self._stmts_to_remove[block]:
                if stmt in block.statements:
                    block.statements.remove(stmt)
