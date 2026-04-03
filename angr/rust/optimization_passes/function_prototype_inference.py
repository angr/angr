from __future__ import annotations
from angr.ailment.expression import VirtualVariable, Const, UnaryOp, BinaryOp, Call
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return, Label, SideEffectStatement
from angr.rust.mixins import CFAMixin, SSAVariableMixin
from angr.rust.analyses.rust_calling_convention import Pathfinder
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.sim_type import RustSimTypeFunction, is_composite_type


class FunctionPrototypeInference(OptimizationPass, CFAMixin, SSAVariableMixin):
    """Infer potential struct/enum argument types and return types for function calls."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Infer potential struct/enum argument types and return types"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SSAVariableMixin.__init__(self, self)

        self.librust = self.project.kb.librust
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _infer_call_prototype(self, call_expr: Call, block):
        """Perform calling convention analysis on target function if it's never analyzed."""
        if (
            not isinstance(call_expr.prototype, RustSimTypeFunction)
            and isinstance(call_expr.target, Const)
            and call_expr.target.value in self.kb.functions
        ):
            func = self.kb.functions[call_expr.target.value]
            if isinstance(func.prototype, RustSimTypeFunction):
                call_expr.prototype = func.prototype
            else:
                post_callsite_block = self.get_one_successor(block) if self.num_successors(block) == 1 else None
                post_callsite_path = (
                    Pathfinder(self._graph).find_forward_path(post_callsite_block) if post_callsite_block else None
                )
                rcc = self.project.analyses.RustCallingConvention(
                    func,
                    callsite_path=Pathfinder(self._graph).find_backward_path(block),
                    post_callsite_path=post_callsite_path,
                    is_call_expr=False,
                    callsite_discriminant_hint=self._detect_callsite_discriminant_hint(post_callsite_path),
                )
                call_expr.prototype = rcc.model.inferred_prototype
                func.prototype = call_expr.prototype
                func.is_prototype_guessed = False

    def _rewrite_retbuf_call(self, call_expr: Call):
        """If the call has a retbuf arg0, rewrite it into Assignment(dst_stack_vvar, call)."""
        if not isinstance(call_expr.prototype, RustSimTypeFunction):
            return None
        if not call_expr.prototype.is_arg0_retbuf:
            return None
        prototype = call_expr.prototype.normalize()
        returnty = prototype.returnty
        if not is_composite_type(returnty):
            return None
        arg0 = call_expr.args[0] if call_expr.args else None
        if not (
            isinstance(arg0, UnaryOp)
            and arg0.op == "Reference"
            and isinstance(arg0.operand, VirtualVariable)
            and arg0.operand.was_stack
        ):
            return None
        call = call_expr.copy()
        call.args = call.args[1:]
        call.bits = returnty.size
        call.prototype = prototype
        dst_vvar = self.new_stack_vvar(arg0.operand.stack_offset, call.bits, arg0.operand.tags)
        dst_vvar.tags["type"] = returnty
        self.project.kb.type_hints.add_type_hint(dst_vvar, returnty)
        return Assignment(idx=None, dst=dst_vvar, src=call, **call.tags)

    def _apply_return_type_hint(self, call_expr: Call, stmt):
        """For non-retbuf calls with composite return type in Assignment(dst, Call), add type hint to dst."""
        if not isinstance(call_expr.prototype, RustSimTypeFunction):
            return
        prototype = call_expr.prototype.normalize()
        returnty = prototype.returnty
        if (
            is_composite_type(returnty)
            and not call_expr.prototype.is_arg0_retbuf
            and isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_reg
        ):
            stmt.dst.tags["type"] = returnty
            self.project.kb.type_hints.add_type_hint(stmt.dst, returnty)

    def _detect_callsite_discriminant_hint(self, post_callsite_path):
        """
        Detect the pattern: if (return_value == discriminant) { early return }
        in the post-callsite path.

        Returns (discriminant_value, is_err) or None:
          - is_err=True:  discriminant_value corresponds to the Err variant
          - is_err=False: discriminant_value corresponds to the Ok variant
        """
        if not post_callsite_path:
            return None

        last_block = post_callsite_path[-1]
        if not last_block.statements:
            return None
        last_stmt = last_block.statements[-1]
        if not isinstance(last_stmt, ConditionalJump):
            return None

        cond = last_stmt.condition
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None

        _, op1 = cond.operands
        if not isinstance(op1, Const):
            return None

        discriminant_value = op1.value

        block_map = {(b.addr, b.idx): b for b in self._graph.nodes}

        true_block = false_block = None
        if isinstance(last_stmt.true_target, Const):
            true_block = block_map.get((last_stmt.true_target.value, last_stmt.true_target_idx))
        if isinstance(last_stmt.false_target, Const):
            false_block = block_map.get((last_stmt.false_target.value, last_stmt.false_target_idx))

        true_early = self._is_early_return_block(true_block, block_map) if true_block else False
        false_early = self._is_early_return_block(false_block, block_map) if false_block else False

        if true_early == false_early:
            return None

        # CmpEQ: true branch → ret == X,  false branch → ret != X
        # CmpNE: true branch → ret != X,  false branch → ret == X
        eq_is_early = true_early if cond.op == "CmpEQ" else false_early
        if eq_is_early:
            return (discriminant_value, True)  # ret == X → early return → X is Err
        return (discriminant_value, False)  # ret != X → early return → X is Ok

    def _is_early_return_block(self, block, block_map, visited=None):
        """Check if a block leads to a simple early return (only labels, register assignments, and returns)."""
        if visited is None:
            visited = set()
        if block in visited:
            return False
        visited.add(block)
        has_return = False
        for stmt in block.statements:
            if isinstance(stmt, Return):
                has_return = True
            elif isinstance(stmt, Jump) and isinstance(stmt.target, Const):
                next_block = block_map.get((stmt.target.value, stmt.target_idx))
                if next_block:
                    return self._is_early_return_block(next_block, block_map, visited)
                return False
            elif isinstance(stmt, Label) or (
                isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg
            ):
                continue
            else:
                return False
        return has_return

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                    call_expr = stmt.expr
                    self._infer_call_prototype(call_expr, block)
                    new_stmt = self._rewrite_retbuf_call(call_expr)
                    if new_stmt is not None:
                        block.statements[stmt_idx] = new_stmt
                elif isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                    call_expr = stmt.src
                    self._infer_call_prototype(call_expr, block)
                    new_stmt = self._rewrite_retbuf_call(call_expr)
                    if new_stmt is not None:
                        block.statements[stmt_idx] = new_stmt
                    else:
                        self._apply_return_type_hint(call_expr, stmt)
        self.fix_stack_vvar_uses()
        self.out_graph = self._graph
