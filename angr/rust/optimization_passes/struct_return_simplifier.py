from collections import defaultdict
from typing import Tuple

from ailment import BinaryOp, AILBlockWalker, Statement, Block
from ailment.expression import VirtualVariable, Const, Load, StackBaseOffset
from ailment.statement import Return, Store, ConditionalJump, Jump, Label, Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.ailment.expression import Struct, Enum
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.rust.mixins.srda_mixin import SRDAMixin
from angr.rust.sim_type import (
    RustSimTypeInt,
    RustSimStruct,
    RustSimTypeFunction,
    RustSimTypeResult,
    RustSimTypeOption,
    EnumVariant,
)


class StructReturnSimplifier(OptimizationPass, SRDAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _get_dst_vvar_and_offset(self, stmt: Store) -> Tuple[VirtualVariable | None, int | None]:
        expr = stmt.addr
        offset = 0
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[0], VirtualVariable)
            and isinstance(expr.operands[1], Const)
        ):
            offset = expr.operands[1].value
            expr = expr.operands[0]
        if isinstance(expr, VirtualVariable):
            return self.get_terminal_vvar(expr), offset
        return None, None

    def _build_struct_ty(self, fields):
        ty_fields = {}
        for offset in sorted(fields.keys()):
            expr = fields[offset]
            arg_ty = RustSimTypeInt(expr.bits, signed=False)
            ty_fields[f"field_{offset}"] = arg_ty
        struct_ty = RustSimStruct(
            ty_fields,
            name=f"struct{sum(field.size if field.size else 0 for field in ty_fields.values()) // 8}",
            pack=True,
        ).with_arch(self.project.arch)
        return struct_ty

    def _has_call(self, block_or_stmt):
        class CallWalker(AILBlockWalker):
            def __init__(self):
                super().__init__()
                self.has_call = False

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self.has_call = True
                return None

        walker = CallWalker()
        if isinstance(block_or_stmt, Block):
            walker.walk(block_or_stmt)
        elif isinstance(block_or_stmt, Statement):
            walker.walk_statement(block_or_stmt)
        return walker.has_call

    def is_return_block(self, block):
        if self._has_call(block):
            return False

        for stmt in reversed(block.statements):
            if isinstance(stmt, (Return, Jump, ConditionalJump, Label)):
                continue
            if isinstance(stmt, Store):
                vvar, _ = self._get_dst_vvar_and_offset(stmt)
                if isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0:
                    return True
            return False
        return True

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
            new_offset = offset - variant.data_offset
            if new_offset >= 0:
                new_fields[new_offset] = v
        struct_ty = self._build_struct_ty(new_fields)
        struct_ty.name = f"struct{struct_ty.size // 8}"
        return Struct(None, new_fields, struct_ty)

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
            if variant and struct.size == variant.size // 8 + variant.discriminant_size:
                new_struct = self._remove_discriminant_from_struct(struct, variant)
                return Enum(None, [new_struct], variant, prototype.returnty.with_arch(self.project.arch))
        return struct

    def collect_ret_expr(self, path):
        fields = {}
        stmts_to_remove = defaultdict(list)
        for block in path:
            for stmt in block.statements:
                if isinstance(stmt, Store):
                    vvar, offset = self._get_dst_vvar_and_offset(stmt)
                    if vvar and vvar.was_parameter and vvar.varid == 0:
                        fields[offset] = stmt.data
                        stmts_to_remove[block].append(stmt)
        existing_vvar = self.get_existing_vvar(fields, path[0])
        if existing_vvar:
            return existing_vvar, stmts_to_remove
        if 0 in fields:
            struct_ty = self._build_struct_ty(fields)
            result = Struct(None, fields, struct_ty)
            return self.try_convert_to_enum(result), stmts_to_remove
        return None, None

    def derive_paths(self, block, max_paths):
        paths = [[block]]
        changed = True
        while len(paths) <= max_paths and changed:
            changed = False
            new_paths = []
            for path in paths:
                last_block = path[-1]
                path_changed = False
                for pred in self._graph.predecessors(last_block):
                    if self.is_return_block(pred):
                        new_path = list(path) + [pred]
                        new_paths.append(new_path)
                        changed = True
                        path_changed = True
                if not path_changed:
                    new_paths.append(path)
            paths = new_paths
        deduplicated_paths = set()
        for path in paths:
            path = list(path)
            while path and (
                all(isinstance(stmt, Label) for stmt in path[-1].statements)
                or isinstance(path[-1].statements[-1], ConditionalJump)
            ):
                path.pop()
            if path:
                deduplicated_paths.add(tuple(path))
        return list(deduplicated_paths)

    def _analyze(self, cache=None):
        ret_blocks = set()
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                ret_blocks.add(block)

        blocks_to_remove = set()
        for ret_block in ret_blocks:
            paths = self.derive_paths(ret_block, max_paths=4)
            for path in paths:
                ret_expr, stmts_to_remove = self.collect_ret_expr(path)
                if ret_expr:
                    for block in path[:-1]:
                        blocks_to_remove.add(block)
                    head_block = path[-1]
                    ret = Return(None, [ret_expr], **head_block.statements[-1].tags)
                    head_block.statements[-1] = ret
                    for block, stmts in stmts_to_remove.items():
                        for stmt in stmts:
                            if stmt in block.statements:
                                block.statements.remove(stmt)
        for block in blocks_to_remove:
            self.remove_block(block)
