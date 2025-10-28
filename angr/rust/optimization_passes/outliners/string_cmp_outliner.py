from archinfo import Endness

from angr.ailment import AILBlockWalker, BinaryOp, Const
from angr.ailment.expression import Load, Convert, StringLiteral
from angr.ailment.statement import ConditionalJump, Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


class StringCmpOutliner(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline string comparisons"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _try_decode_str(self, value, size):
        try:
            byteorder = "big" if self.project.arch.memory_endness == Endness.BE else "little"
            decoded_str = int.to_bytes(value, size, byteorder).decode("UTF-8")
            decoded_str = (
                decoded_str if decoded_str.replace("\n", "").replace("\t", "").replace("\r", "").isprintable() else None
            )
            return decoded_str
        except Exception:
            return None

    def _extract_cmp(self, expr):
        if isinstance(expr, BinaryOp) and expr.op == "CmpEQ" and isinstance(expr.operands[1], Const):
            expected_value = expr.operands[1].value
            expected_value_size = expr.operands[1].size
            expr = expr.operands[0]
            if isinstance(expr, BinaryOp) and expr.op == "Xor" and expected_value == 0:
                lhs, rhs = expr.operands
                expr = lhs
                if isinstance(rhs, Const):
                    expected_value = rhs.value
            if isinstance(expr, Convert):
                expected_value_size = expr.from_bits // 8
                expr = expr.operand
            decoded_str = self._try_decode_str(expected_value, expected_value_size)
            if decoded_str and isinstance(expr, Load):
                str_expr = expr.addr
                offset = 0
                if (
                    isinstance(str_expr, BinaryOp)
                    and str_expr.op == "Add"
                    and isinstance(str_expr.operands[1], Const)
                    and str_expr.operands[1].value > 0
                ):
                    offset = str_expr.operands[1].value
                    str_expr = str_expr.operands[0]
                return str_expr, offset, decoded_str
        return None

    def _extract_cmps(self, expr):
        cmps = []
        if isinstance(expr, BinaryOp) and expr.op == "LogicalAnd":
            for operand in expr.operands:
                result = self._extract_cmps(operand)
                if result:
                    cmps += result
                else:
                    return None
        else:
            cmp = self._extract_cmp(expr)
            if cmp:
                cmps.append(cmp)
            else:
                return None
        return cmps if len(cmps) else None

    def _process_condition(self, stmt_idx, stmt, block):
        expr = stmt.condition
        if isinstance(expr, BinaryOp) and expr.op in ("CmpEQ", "LogicalAnd"):
            cmps = self._extract_cmps(expr)
            if cmps:
                cmps = sorted(cmps, key=lambda t: t[1])
                str_var = cmps[0][0]
                expected_offset = 0
                combined_str = ""
                for expr, offset, decoded_str in cmps:
                    if offset != expected_offset:
                        return None
                    expected_offset += len(decoded_str)
                    if not expr.likes(str_var):
                        return None
                    combined_str += decoded_str
                str_literal = StringLiteral(None, combined_str, str_var.bits)
                new_cond = BinaryOp(None, "CmpEQ", [str_var, str_literal], **stmt.condition.tags)
                # name = "<alloc::string::String as core::cmp::PartialEq>::eq"
                # call = Call(
                #     idx=None,
                #     target=name,
                #     prototype=self.kb.librust.get_prototype(name).with_arch(self.project.arch).normalize(),
                #     args=[str_var, StringLiteral(None, combined_str, self.project.arch.bits * 2)],
                #     ret_expr=None,
                #     **stmt.condition.tags,
                # )
                # call.bits = 1
                new_stmt = stmt.copy()
                new_stmt.condition = new_cond
                block.statements[stmt_idx] = new_stmt
                return new_stmt
        return None

    def _analyze(self, cache=None):
        walker = AILBlockWalker(stmt_handlers={ConditionalJump: self._process_condition})
        for block in self._graph.nodes:
            walker.walk(block)

        self.out_graph = self._graph
