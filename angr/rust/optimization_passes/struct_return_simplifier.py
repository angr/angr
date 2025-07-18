from collections import defaultdict

from angr.ailment.expression import VirtualVariable, Const, Load, StackBaseOffset, Struct, Enum
from angr.ailment.statement import Return, Store
from angr.rust.utils.ail import extract_vvar_and_offset
from angr.rust.analyses.rust_calling_convention import Pathfinder
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.rust.mixins.srda_mixin import SRDAMixin
from angr.rust.sim_type import (
    RustSimTypeInt,
    RustSimStruct,
    RustSimTypeFunction,
    RustSimTypeResult,
    RustSimTypeOption,
    EnumVariant,
    RustSimTypeUnit,
)


class StructReturnSimplifier(OptimizationPass, SRDAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

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

    def _is_stack_mem(self, expr):
        offset, size = None, None
        if isinstance(expr, Load) and isinstance(expr.addr, StackBaseOffset):
            offset = expr.addr.offset
            size = expr.size
        elif isinstance(expr, VirtualVariable) and expr.was_stack:
            offset = expr.stack_offset
            size = expr.size
        return offset, size

    def get_existing_vvar(self, fields, block):
        cur_offset = 0
        src_stack_offset = None
        if 0 in fields:
            offset, _ = self._is_stack_mem(fields[0])
            if offset is not None:
                src_stack_offset = offset
        if src_stack_offset is not None:
            while cur_offset in fields:
                expr = fields[cur_offset]
                offset, size = self._is_stack_mem(expr)
                if offset == src_stack_offset + cur_offset:
                    cur_offset += size
                else:
                    return None
        if cur_offset == sum(field.size for field in fields.values()):
            vvar = self.get_stack_vvar_by_insn(
                src_stack_offset, block.statements[-1].ins_addr, block.idx, size=cur_offset
            )
            return vvar
        return None

    def _remove_discriminant_from_struct(self, struct: Struct, variant: EnumVariant):
        new_fields = {}
        for offset, v in struct.fields.items():
            new_offset = offset - variant.first_field_offset
            if new_offset >= 0:
                new_fields[new_offset] = v
        struct_ty = self._build_struct_ty(new_fields)
        return Struct(None, struct_ty.name, new_fields, struct_ty.offsets, struct_ty.size)

    def try_convert_to_enum(self, struct: Struct):
        prototype = self._func.prototype
        if isinstance(prototype, RustSimTypeFunction):
            prototype = prototype.normalize()
            discriminant = None
            if isinstance(struct.fields[0], Const):
                discriminant = struct.fields[0].value
            variant = None
            if isinstance(prototype.returnty, (RustSimTypeResult, RustSimTypeOption)):
                variant = prototype.returnty.get_variant(discriminant)
                if not variant and discriminant is not None:
                    variant = prototype.returnty.get_variant(None)
            if variant and struct.size == variant.size:
                new_expr = self._remove_discriminant_from_struct(struct, variant)
                if len(new_expr.fields) == 1 and 0 in new_expr.fields:
                    new_expr = new_expr.fields[0]
                return Enum(None, variant.name, [new_expr], prototype.returnty.with_arch(self.project.arch).size)
        return struct

    def collect_ret_expr(self, path):
        fields = {}
        stmts_to_remove = defaultdict(list)
        for block in path:
            for stmt in block.statements:
                if isinstance(stmt, Store):
                    vvar, offset = extract_vvar_and_offset(stmt.addr)
                    if vvar and vvar.was_parameter and vvar.varid == 0:
                        fields[offset] = stmt.data
                        stmts_to_remove[block].append(stmt)
        existing_vvar = self.get_existing_vvar(fields, path[0])
        if existing_vvar:
            return existing_vvar, stmts_to_remove
        if 0 in fields:
            struct_ty = self._build_struct_ty(fields)
            result = Struct(None, struct_ty.name, fields, struct_ty.offsets, struct_ty.size)
            return self.try_convert_to_enum(result), stmts_to_remove
        return None, None

    def _analyze(self, cache=None):
        ret_blocks = set()
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                ret_blocks.add(block)

        blocks_to_remove = set()
        paths = Pathfinder(self._graph, self).find_ret2arg0_paths()
        for path in paths:
            ret_expr, stmts_to_remove = self.collect_ret_expr(path)
            if ret_expr:
                for block in path[1:]:
                    blocks_to_remove.add(block)
                head_block = path[0]
                ret = Return(None, [ret_expr], **head_block.statements[-1].tags)
                head_block.statements[-1] = ret
                for block, stmts in stmts_to_remove.items():
                    for stmt in stmts:
                        if stmt in block.statements:
                            block.statements.remove(stmt)
        for block in blocks_to_remove:
            self.remove_block(block)
