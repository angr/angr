# pylint:disable=no-self-use,unused-argument,too-many-boolean-expressions
from __future__ import annotations
from typing import TYPE_CHECKING

from angr.analyses import Analysis, register_analysis
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker, CVariable, CConstant, CBinaryOp

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import (
        CAssignment,
        CFunction,
        CWhileLoop,
        CDoWhileLoop,
        CForLoop,
        CBreak,
        CStatements,
    )


class ASTNodeBase:
    """
    The base node for AST nodes used in loop analysis.
    """


class VarNode(ASTNodeBase):
    """
    Represents a variable node in the AST; corresponds to a virtual variable in AIL.
    """

    def __init__(self, var_ident: str):
        self.var_ident = var_ident

    def __repr__(self):
        return self.var_ident

    def __eq__(self, other):
        if not isinstance(other, VarNode):
            return False
        return self.var_ident == other.var_ident


class ConstNode(ASTNodeBase):
    """
    Represents a constant value.
    """

    def __init__(self, value: int):
        self.value = value

    def __repr__(self):
        return str(self.value)

    def __eq__(self, other):
        if not isinstance(other, ConstNode):
            return False
        return self.value == other.value


class BinOpNode(ASTNodeBase):
    """
    Represents a binary operation between a variable and a constant.
    """

    def __init__(self, op: str, lhs: VarNode, rhs: ConstNode):
        self.op = op
        self.lhs = lhs
        self.rhs = rhs

    def __repr__(self):
        return f"({self.lhs} {self.op} {self.rhs.value})"

    def __eq__(self, other):
        if not isinstance(other, BinOpNode):
            return False
        return self.op == other.op and self.lhs == other.lhs and self.rhs == other.rhs


class AssignmentNode(ASTNodeBase):
    """
    Represents an assignment operation in the AST.
    """

    def __init__(self, lhs: VarNode, rhs: ASTNodeBase):
        self.lhs = lhs
        self.rhs = rhs

    def __repr__(self):
        return f"{self.lhs} = {self.rhs}"

    def __eq__(self, other):
        if not isinstance(other, AssignmentNode):
            return False
        return self.lhs == other.lhs and self.rhs == other.rhs


class AssignmentToASTVisitor(CStructuredCodeWalker):
    """
    A visitor that converts AIL assignments into AST nodes.
    """

    def handle_CAssignment(self, obj: CAssignment) -> AssignmentNode | None:
        lhs = self.handle(obj.lhs)
        if lhs is None:
            return None
        rhs = self.handle(obj.rhs)
        if rhs is None:
            return None
        return AssignmentNode(lhs, rhs)

    def handle_CVariable(self, obj: CVariable) -> VarNode | None:
        if obj.unified_variable is None:
            return None
        return VarNode(obj.unified_variable.ident)

    def handle_CBinaryOp(self, obj: CBinaryOp) -> BinOpNode | None:
        match obj.op:
            case "Add":
                op = "+"
            case "Sub":
                op = "-"
            case "CmpEQ":
                op = "=="
            case "CmpNE":
                op = "!="
            case "CmpLT":
                op = "<"
            case "CmpLE":
                op = "<="
            case "CmpGT":
                op = ">"
            case "CmpGE":
                op = ">="
            case _:
                return None

        left = self.handle(obj.lhs)
        right = self.handle(obj.rhs)
        if not isinstance(left, VarNode) or not isinstance(right, ConstNode):
            return None

        return BinOpNode(op, left, right)

    def handle_CConstant(self, obj: CConstant) -> ConstNode | None:
        if isinstance(obj.value, int):
            return ConstNode(obj.value)
        return None


class LoopBodyControlStatementCollector(CStructuredCodeWalker):
    """
    A visitor that determines if there are control statements (break, continue, goto) within a loop body.
    """

    def __init__(self):
        super().__init__()
        self.has_break = False
        self.has_continue = False
        self.has_goto = False

    def handle_CBreak(self, obj: CBreak):
        self.has_break = True

    def handle_CContinue(self, obj):
        self.has_continue = True

    def handle_CGoto(self, obj):
        self.has_goto = True

    def handle_CSwitchCase(self, obj):
        return

    def handle_CForLoop(self, obj):
        return

    def handle_CDoWhileLoop(self, obj):
        return

    def handle_CWhileLoop(self, obj):
        return


class LoopBodyAssignmentCollector(CStructuredCodeWalker):
    """
    A visitor that collects assignments to specific variables within a loop body.
    """

    def __init__(self, var_idents: set[str]):
        super().__init__()

        self.var_idents = var_idents
        self.assignments: list[AssignmentNode] = []

    def handle_CAssignment(self, obj: CAssignment):
        include = False

        if isinstance(obj.lhs, CVariable) and obj.lhs.unified_variable.ident in self.var_idents:
            include = True
        elif isinstance(obj.rhs, CVariable):
            if obj.rhs.unified_variable.ident in self.var_idents:
                include = True
                if isinstance(obj.lhs, CVariable) and obj.lhs.unified_variable is not None:
                    self.var_idents.add(obj.lhs.unified_variable.ident)
        elif isinstance(obj.rhs, CBinaryOp) and (
            (isinstance(obj.rhs.lhs, CVariable) and obj.rhs.lhs.unified_variable.ident in self.var_idents)
            or (isinstance(obj.rhs.rhs, CVariable) and obj.rhs.rhs.unified_variable.ident in self.var_idents)
        ):
            include = True
            if isinstance(obj.lhs, CVariable) and obj.lhs.unified_variable is not None:
                self.var_idents.add(obj.lhs.unified_variable.ident)

        if include:
            ast_ = AssignmentToASTVisitor().handle(obj)
            if ast_ is not None:
                self.assignments.append(ast_)

    def handle_CIfElse(self, obj):
        return

    def handle_CSwitchCase(self, obj):
        return

    def handle_CForLoop(self, obj):
        return

    def handle_CDoWhileLoop(self, obj):
        return

    def handle_CWhileLoop(self, obj):
        return


class LoopVisitor(CStructuredCodeWalker):
    """
    A visitor that analyzes loop structures in CStructuredCode and collects relevant information for loops.
    """

    def __init__(self):
        super().__init__()

        self.var_values: dict[str, int | None] = {}
        self.result: dict[str, dict] = {}
        self._block_addrs_stack: list[set[int]] = []

    def _enter_loop(self):
        self._block_addrs_stack.append(set())

    def _leave_loop(self):
        if self._block_addrs_stack:
            self._block_addrs_stack.pop()

    def _push_block_addr(self, addr: int):
        for frame in self._block_addrs_stack:
            frame.add(addr)

    def _top_loop_block_addrs(self) -> set[int]:
        return self._block_addrs_stack[-1] if self._block_addrs_stack else set()

    def handle_CIfElse(self, obj):
        addr = obj.tags.get("ins_addr", None)
        if addr is not None:
            self._push_block_addr(addr)
        return super().handle_CIfElse(obj)

    def handle_CStatements(self, obj: CStatements):
        self._push_block_addr(obj.addr)
        return super().handle_CStatements(obj)

    def handle_CAssignment(self, obj: CAssignment):
        if isinstance(obj.lhs, CVariable) and obj.lhs.unified_variable is not None:
            self.var_values[obj.lhs.unified_variable.ident] = (
                obj.rhs.value if isinstance(obj.rhs, CConstant) and isinstance(obj.rhs.value, int) else None
            )
        return super().handle_CAssignment(obj)

    def handle_CWhileLoop(self, obj: CWhileLoop):
        self.result[obj.idx] = {
            "loop_type": "while",
        }

        self._enter_loop()
        ret = super().handle_CWhileLoop(obj)
        if obj.idx in self.result:
            self.result[obj.idx]["block_addrs"] = sorted(self._top_loop_block_addrs())
        self._leave_loop()
        return ret

    def handle_CDoWhileLoop(self, obj: CDoWhileLoop):
        cond, body = obj.condition, obj.body
        self.result[obj.idx] = {
            "loop_type": "do-while",
        }
        comp_ops = {"CmpNE", "CmpEQ", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}
        if isinstance(cond, CBinaryOp) and cond.op in comp_ops:  # noqa:SIM102
            # parse the condition variable and constant if possible
            if isinstance(cond.lhs, CVariable):
                body_visitor = LoopBodyAssignmentCollector({cond.lhs.unified_variable.ident})
                body_visitor.handle(body)

                cond_node: BinOpNode | None = AssignmentToASTVisitor().handle(cond)
                if cond_node is not None and body_visitor.assignments:

                    assignments = body_visitor.assignments

                    # case 3:
                    # a = N
                    # do { b = a; c = b + A; a = c; } while (b ? M)
                    # we convert it into case 2 by eliminating c
                    if len(assignments) == 3:
                        assign1, assign2, assign3 = assignments  # pylint:disable=unbalanced-tuple-unpacking
                        if (
                            isinstance(assign2.rhs, BinOpNode)
                            and assign2.rhs.op in {"+", "-"}
                            and assign3.rhs == assign2.lhs
                            and isinstance(assign1, AssignmentNode)
                            and isinstance(assign1.rhs, VarNode)
                            and assign3.lhs == assign1.rhs
                            and assign1.lhs == cond_node.lhs
                        ):
                            assignments = [assign1, AssignmentNode(assign3.lhs, assign2.rhs)]

                    # case 2:
                    # a = N
                    # do { b = a; ...; a = b + A; } while (b ? M)
                    # we convert it into case 1
                    if len(assignments) == 2:
                        assign1, assign2 = assignments
                        if isinstance(assign2.rhs, BinOpNode) and assign2.rhs.op in {"+", "-"}:  # noqa:SIM102
                            if (
                                assign1.lhs == assign2.rhs.lhs
                                and assign1.rhs == assign2.lhs
                                and assign1.lhs == cond_node.lhs
                            ):
                                v = assign2.lhs

                                # update cond_node and assignments
                                new_const_value = cond_node.rhs.value
                                if assign2.rhs.op == "+":
                                    new_const_value += assign2.rhs.rhs.value
                                elif assign2.rhs.op == "-":
                                    new_const_value -= assign2.rhs.rhs.value
                                else:
                                    new_const_value = None
                                if new_const_value is not None:
                                    cond_node = BinOpNode(cond_node.op, v, ConstNode(new_const_value))
                                    # update assignments
                                    binop = BinOpNode(assign2.rhs.op, v, assign2.rhs.rhs)
                                    assignments = [AssignmentNode(v, binop)]

                    # case 1:
                    # a = N
                    # do { a = a + A; ,,, } while (a ? M)
                    init_value = None
                    if cond_node.lhs.var_ident in self.var_values:
                        init_value = self.var_values[cond_node.lhs.var_ident]
                    if init_value is not None and len(assignments) == 1:
                        assign = assignments[0]
                        step = None
                        if (
                            isinstance(assign.rhs, BinOpNode)
                            and assign.rhs.lhs.var_ident == cond_node.lhs.var_ident
                            and isinstance(assign.rhs.rhs, ConstNode)
                        ):
                            match assign.rhs.op:
                                case "+":
                                    step = assign.rhs.rhs.value
                                case "-":
                                    step = -assign.rhs.rhs.value
                                case _:
                                    step = None

                        if step is not None:
                            cond_op = cond_node.op
                            bound = cond_node.rhs.value

                            match cond_op:
                                case "==":
                                    max_iterations = 2 if bound == init_value + step else 1
                                case "!=":
                                    if (bound - init_value) % step == 0:
                                        max_iterations = (bound - init_value) // step
                                        if max_iterations <= 0:
                                            max_iterations = None
                                    else:
                                        max_iterations = None
                                case "<":
                                    max_iterations = (bound - init_value + step - 1) // step
                                    if max_iterations <= 0:
                                        max_iterations = None
                                case "<=":
                                    max_iterations = (bound - init_value + step - 2) // step
                                    if max_iterations <= 0:
                                        max_iterations = None
                                case ">":
                                    max_iterations = (bound - init_value) // step
                                    if max_iterations <= 0:
                                        max_iterations = None
                                case ">=":
                                    max_iterations = (bound - 1 - init_value) // step
                                    if max_iterations <= 0:
                                        max_iterations = None
                                case _:
                                    max_iterations = None

                            controls = LoopBodyControlStatementCollector()
                            controls.handle(obj)
                            fixed_iterations = not (controls.has_goto or controls.has_break or controls.has_continue)

                            self.result[obj.idx] = {
                                "loop_type": "do-while",
                                "loop_variable": cond_node.lhs.var_ident,
                                "initial_value": init_value,
                                "condition_op": cond_op,
                                "bound": bound,
                                "step": step,
                                "max_iterations": max_iterations,
                                "fixed_iterations": fixed_iterations,
                            }

        self._enter_loop()
        ret = super().handle_CDoWhileLoop(obj)
        if obj.idx in self.result:
            self.result[obj.idx]["block_addrs"] = sorted(self._top_loop_block_addrs())
        self._leave_loop()
        return ret

    def handle_CForLoop(self, obj: CForLoop):
        self.result[obj.idx] = {
            "loop_type": "for",
        }
        self._enter_loop()
        ret = super().handle_CForLoop(obj)
        if obj.idx in self.result:
            self.result[obj.idx]["block_addrs"] = sorted(self._top_loop_block_addrs())
        self._leave_loop()
        return ret


class LoopAnalysis(Analysis):
    """
    Analyze loop nodes in a structured C code representation and extract relevant information about the loop, including
    - Loop block addresses
    - Loop exits
    - Loop type
    - Loop condition
    - Max iterations
    - Fixed iterations
    """

    def __init__(self, cfunc: CFunction):
        super().__init__()

        self.cfunc = cfunc
        self.result: dict[str, dict] = {}

        self._analyze()

    def _analyze(self):
        visitor = LoopVisitor()
        visitor.handle(self.cfunc)
        self.result = visitor.result


register_analysis(LoopAnalysis, "LoopAnalysis")
