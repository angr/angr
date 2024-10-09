from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections import defaultdict
import logging

from ailment import AILBlockWalkerBase, AILBlockWalker
from ailment.statement import Assignment, Call
from ailment.expression import VirtualVariable, Phi, Const, Convert, BinaryOp
from aiohttp.web_routedef import static

from angr.knowledge_plugins.key_definitions import Definition
from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.utils.ail import is_phi_assignment

if TYPE_CHECKING:
    from ailment.expression import (
        Expression,
        Load,
        UnaryOp,
        ITE,
        DirtyExpression,
        VEXCCallExpression,
    )
    from ailment.statement import Statement
    from ailment.block import Block


_l = logging.getLogger(__name__)


class ExprNarrowingInfo:
    """
    Stores the analysis result of _narrowing_needed().
    """

    __slots__ = ("narrowable", "to_size", "use_exprs", "phi_vars")

    def __init__(
        self,
        narrowable: bool,
        to_size: int | None = None,
        use_exprs: list[tuple[atoms.VirtualVariable, CodeLocation, tuple[str, tuple[Expression, ...]]]] | None = None,
        phi_vars: set[atoms.VirtualVariable] | None = None,
    ):
        self.narrowable = narrowable
        self.to_size = to_size
        self.use_exprs = use_exprs
        self.phi_vars = phi_vars


class NarrowingInfoExtractor(AILBlockWalkerBase):
    """
    Walks a statement or an expression and extracts the operations that are applied on the given expression.

    For example, for target expression rax, `(rax & 0xff) + 0x1` means the following operations are applied on `rax`:
    rax & 0xff
    (rax & 0xff) + 0x1

    The previous expression is always used in the succeeding expression.
    """

    def __init__(self, target_expr: Expression):
        super().__init__()
        self._target_expr = target_expr
        self.operations = []

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if expr == self._target_expr:
            # we are done!
            return True
        has_target_expr = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        if has_target_expr:
            # record the current operation
            self.operations.append(expr)
            return True
        return False

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        r = False
        if expr.args:
            for i, arg in enumerate(expr.args):
                r |= self._handle_expr(i, arg, stmt_idx, stmt, block)
        return r

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        r = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        return r

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Block | None):
        r = self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        r |= self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        return r

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        return self._handle_expr(0, expr.dirty_expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        r = False
        for idx, operand in enumerate(expr.operands):
            r |= self._handle_expr(idx, operand, stmt_idx, stmt, block)
        return r


StmtLocType = tuple[int, int | None, int]


class ExpressionNarrower(AILBlockWalker):
    """
    Narrows an expression regardless of whether the expression is a definition or a use.
    """

    def __init__(
        self, project, rd, narrowables, addr2blocks: dict[tuple[int, int | None], Block], new_blocks: dict[Block, Block]
    ):
        super().__init__(update_block=False)

        self.project = project
        self._rd = rd
        self._addr2blocks = addr2blocks
        self._new_blocks = new_blocks

        # each expression can be replaced by one or more than one expressions; the list of replacements is ordered.
        # the first replacement can be generated by the definition, and the rest can be generated by the uses.
        # consider the following case:
        #     v8<64> = v6 & 0xffff_ffff
        #     v13<64> = v8<64>
        # and we want to narrow both v13 and v8 to 32-bit variables.
        # we will replace v13<64> with v13<32>, v8<64> with Convert(64->32, v8<64>), then v8<64> with v8<32>.
        # so we end up with
        #     v13<32> = Convert(64->32, Convert(32->64, v8<32>))
        # other simplifications will collapse the nested Convert expressions.
        self.replacements: dict[StmtLocType, dict[Expression, list[Expression]]] = self._parse_narrowables(narrowables)
        self.narrowed_any = False

    def walk(self, block: Block):
        self.narrowed_any = False
        return super().walk(block)

    @staticmethod
    def _codeloc2tuple(codeloc: CodeLocation) -> StmtLocType:
        return codeloc.block_addr, codeloc.block_idx, codeloc.stmt_idx

    def _parse_narrowables(self, narrowables) -> dict[StmtLocType, dict[Expression, list[Expression]]]:

        all_replacements = defaultdict(dict)

        for def_, narrow_info in narrowables:
            # replace the definition expression
            if not isinstance(def_.codeloc, ExternalCodeLocation):
                replacements = self._generate_replacement_defexprs(def_, narrow_info)
                for codeloc, replacement in replacements.items():
                    for src_expr, dst_expr in replacement.items():
                        if src_expr not in all_replacements[codeloc]:
                            all_replacements[codeloc][src_expr] = []
                        all_replacements[codeloc][src_expr].append(dst_expr)

            # replace the used expressions
            use_exprs = list(narrow_info.use_exprs)
            if narrow_info.phi_vars:
                for phi_var in narrow_info.phi_vars:
                    loc = self._rd.all_vvar_definitions[phi_var]
                    old_block = self._addr2blocks.get((loc.block_addr, loc.block_idx))
                    the_block = self._new_blocks.get(old_block, old_block)
                    stmt = the_block.statements[loc.stmt_idx]
                    assert is_phi_assignment(stmt)

                    for _, vvar in stmt.src.src_and_vvars:
                        if vvar is not None and vvar.varid == def_.atom.varid:
                            use_exprs.append((vvar, loc, ("phi-src-expr", (vvar,))))

            for use_atom, use_loc, (use_type, use_expr_tpl) in use_exprs:
                use_loc = use_loc.block_addr, use_loc.block_idx, use_loc.stmt_idx
                replacements = self._generate_replacement_useexprs(
                    def_, narrow_info, use_atom, use_loc, use_type, use_expr_tpl
                )
                for codeloc, replacement in replacements.items():
                    for src_expr, dst_expr in replacement.items():
                        if src_expr not in all_replacements[codeloc]:
                            all_replacements[codeloc][src_expr] = []
                        all_replacements[codeloc][src_expr].append(dst_expr)

        return all_replacements

    def _generate_replacement_defexprs(
        self, def_: Definition, narrow_info: ExprNarrowingInfo
    ) -> dict[StmtLocType, dict[Expression, Expression]]:
        old_block = self._addr2blocks.get((def_.codeloc.block_addr, def_.codeloc.block_idx))
        if old_block is None:
            # this definition might be inside a callee function, which is why the block does not exist
            # ignore it
            return {}

        the_block = self._new_blocks.get(old_block, old_block)
        stmt = the_block.statements[def_.codeloc.stmt_idx]
        if is_phi_assignment(stmt):
            new_assignment_dst = VirtualVariable(
                stmt.dst.idx,
                stmt.dst.varid,
                narrow_info.to_size * self.project.arch.byte_width,
                category=def_.atom.category,
                oident=def_.atom.oident,
                **stmt.dst.tags,
            )
            new_src_and_vvars = []
            for src, vvar in stmt.src.src_and_vvars:
                if vvar is not None and vvar.varid == stmt.dst.varid:
                    new_vvar = VirtualVariable(
                        vvar.idx,
                        vvar.varid,
                        narrow_info.to_size * self.project.arch.byte_width,
                        category=vvar.category,
                        oident=vvar.oident,
                        **vvar.tags,
                    )
                else:
                    new_vvar = vvar
                new_src_and_vvars.append((src, new_vvar))
            new_assignment_src = Phi(
                stmt.src.idx,
                narrow_info.to_size * self.project.arch.byte_width,
                new_src_and_vvars,
                **stmt.src.tags,
            )
            return {self._codeloc2tuple(def_.codeloc): {stmt.dst: new_assignment_dst, stmt.src: new_assignment_src}}

        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
            new_assignment_dst = VirtualVariable(
                stmt.dst.idx,
                stmt.dst.varid,
                narrow_info.to_size * self.project.arch.byte_width,
                category=def_.atom.category,
                oident=def_.atom.oident,
                **stmt.dst.tags,
            )
            new_assignment_src = Convert(
                stmt.src.idx,  # FIXME: This is a hack
                stmt.src.bits,
                narrow_info.to_size * self.project.arch.byte_width,
                False,
                stmt.src,
                **stmt.src.tags,
            )
            return {self._codeloc2tuple(def_.codeloc): {stmt.dst: new_assignment_dst, stmt.src: new_assignment_src}}

        if isinstance(stmt, Call):
            if stmt.ret_expr is not None:
                tags = dict(stmt.ret_expr.tags)
                tags["reg_name"] = self.project.arch.translate_register_name(
                    def_.atom.reg_offset, size=narrow_info.to_size
                )
                new_retexpr = VirtualVariable(
                    stmt.ret_expr.idx,
                    stmt.ret_expr.varid,
                    narrow_info.to_size * self.project.arch.byte_width,
                    category=def_.atom.category,
                    oident=def_.atom.oident,
                    **stmt.ret_expr.tags,
                )
                return {self._codeloc2tuple(def_.codeloc): {stmt.ret_expr: new_retexpr}}

        return {}

    def _generate_replacement_useexprs(
        self, def_, narrow_info, use_atom, use_loc: StmtLocType, use_type, use_expr_tpl
    ) -> dict[StmtLocType, dict[Expression, Expression]]:

        if (
            isinstance(use_expr_tpl[0], VirtualVariable)
            and use_expr_tpl[0].was_reg
            and narrow_info.to_size == use_expr_tpl[0].size
        ):
            # don't replace registers to the same registers
            return {}
        if use_atom.varid != def_.atom.varid:
            # don't replace this use - it will be replaced later
            return {}

        if use_type in {"expr", "mask", "convert"}:
            # the first used expr
            use_expr_0 = use_expr_tpl[0]
            new_use_expr_0 = VirtualVariable(
                use_expr_0.idx,
                def_.atom.varid,
                narrow_info.to_size * self.project.arch.byte_width,
                category=def_.atom.category,
                oident=def_.atom.oident,
                **use_expr_0.tags,
            )

            # the second used expr (if it exists)
            if len(use_expr_tpl) == 2:
                use_expr_1 = use_expr_tpl[1]
                assert isinstance(use_expr_1, BinaryOp)
                con = use_expr_1.operands[1]
                assert isinstance(con, Const)
                new_use_expr_1 = BinaryOp(
                    use_expr_1.idx,
                    use_expr_1.op,
                    [
                        new_use_expr_0,
                        Const(con.idx, con.variable, con.value, new_use_expr_0.bits, **con.tags),
                    ],
                    use_expr_1.signed,
                    floating_point=use_expr_1.floating_point,
                    rounding_mode=use_expr_1.rounding_mode,
                    **use_expr_1.tags,
                )

                if use_expr_1.size > new_use_expr_1.size:
                    new_use_expr_1 = Convert(
                        None,
                        new_use_expr_1.bits,
                        use_expr_1.bits,
                        False,
                        new_use_expr_1,
                        **new_use_expr_1.tags,
                    )

                return {use_loc: {use_expr_1: new_use_expr_1}}
            elif len(use_expr_tpl) == 1:
                if use_expr_0.size > new_use_expr_0.size:
                    new_use_expr_0 = Convert(
                        None,
                        new_use_expr_0.bits,
                        use_expr_0.bits,
                        False,
                        new_use_expr_0,
                        **new_use_expr_0.tags,
                    )
                return {use_loc: {use_expr_0: new_use_expr_0}}
            else:
                _l.warning("Nothing to replace at %s.", use_loc)
                return {}

        if use_type == "phi-src-expr":
            # the size of the replaced variable will be different from its original size, and it's expected
            use_expr = use_expr_tpl[0]
            new_use_expr = VirtualVariable(
                use_expr.idx,
                def_.atom.varid,
                narrow_info.to_size * self.project.arch.byte_width,
                category=def_.atom.category,
                oident=def_.atom.oident,
                **use_expr.tags,
            )
            return {use_loc: {use_expr: new_use_expr}}

        if use_type == "binop-convert":
            use_expr_0 = use_expr_tpl[0]
            new_use_expr_0 = VirtualVariable(
                use_expr_0.idx,
                def_.atom.varid,
                narrow_info.to_size * self.project.arch.byte_width,
                category=def_.atom.category,
                oident=def_.atom.oident,
                **use_expr_0.tags,
            )

            use_expr_1: BinaryOp = use_expr_tpl[1]
            # build the new use_expr_1
            new_use_expr_1_operands = {}
            if use_expr_1.operands[0] is use_expr_0:
                new_use_expr_1_operands[0] = new_use_expr_0
                other_operand = use_expr_1.operands[1]
            else:
                new_use_expr_1_operands[1] = new_use_expr_0
                other_operand = use_expr_1.operands[0]
            use_expr_2: Convert = use_expr_tpl[2]
            if other_operand.bits == use_expr_2.from_bits:
                new_other_operand = Convert(None, use_expr_2.from_bits, use_expr_2.to_bits, False, other_operand)
            else:
                # Some operations, like Sar and Shl, have operands with different sizes
                new_other_operand = other_operand

            if 0 in new_use_expr_1_operands:
                new_use_expr_1_operands[1] = new_other_operand
            else:
                new_use_expr_1_operands[0] = new_other_operand

            # build new use_expr_1
            new_use_expr_1 = BinaryOp(
                use_expr_1.idx,
                use_expr_1.op,
                [new_use_expr_1_operands[0], new_use_expr_1_operands[1]],
                use_expr_1.signed,
                bits=narrow_info.to_size * 8,
                floating_point=use_expr_1.floating_point,
                rounding_mode=use_expr_1.rounding_mode,
                **use_expr_1.tags,
            )

            return {
                use_loc: {
                    use_expr_2: use_expr_2.operand,  # first remove the old conversion
                    use_expr_1: new_use_expr_1,  # then replace use_expr_1
                }
            }

        return {}

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        loc: StmtLocType = block.addr, block.idx, stmt_idx

        if loc in self.replacements:
            if expr in self.replacements[loc] and self.replacements[loc][expr]:
                print(f"Replaced! {expr} -> {self.replacements[loc][expr]}")
                self.narrowed_any = True
                first_replacement_expr = self.replacements[loc][expr][0]
                all_replacements = self.replacements[loc][expr]
                self.replacements[loc][expr] = self.replacements[loc][expr][1:]
                new_expr = super()._handle_expr(expr_idx, first_replacement_expr, stmt_idx, stmt, block)
                self.replacements[loc][expr] = all_replacements
                return new_expr if new_expr is not None else first_replacement_expr
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
