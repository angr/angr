# pylint:disable=arguments-differ,arguments-renamed,isinstance-second-argument-not-valid-type
from typing import Optional, Union, TYPE_CHECKING
import logging

import claripy
from ailment import Stmt, Expr

from ...utils.constants import is_alignment_mask
from ...engines.light import SimEngineLightAILMixin
from ...sim_variable import SimStackVariable, SimMemoryVariable
from .engine_base import SimEnginePropagatorBase
from .prop_value import PropValue, Detail

if TYPE_CHECKING:
    from .propagator import PropagatorAILState
    from angr.code_location import CodeLocation

l = logging.getLogger(name=__name__)


class SimEnginePropagatorAIL(
    SimEngineLightAILMixin,
    SimEnginePropagatorBase,
):
    """
    The AIl engine for Propagator.
    """

    state: 'PropagatorAILState'

    def _is_top(self, expr: Union[claripy.ast.Base,Expr.StackBaseOffset]) -> bool:
        if isinstance(expr, Expr.StackBaseOffset):
            return False
        return super()._is_top(expr)

    def extract_offset_to_sp(self, expr: Union[claripy.ast.Base,Expr.StackBaseOffset]) -> Optional[int]:
        if isinstance(expr, Expr.StackBaseOffset):
            return expr.offset
        elif isinstance(expr, Expr.Expression):
            # not supported
            return None
        return super().extract_offset_to_sp(expr)

    #
    # AIL statement handlers
    #

    def _ail_handle_Assignment(self, stmt):
        """

        :param Stmt.Assignment stmt:
        :return:
        """

        src = self._expr(stmt.src)
        dst = stmt.dst

        if type(dst) is Expr.Tmp:
            self.state.store_temp(dst.tmp_idx, src)
            self.state.temp_expressions[dst.tmp_idx] = stmt.src

        elif type(dst) is Expr.Register:
            if src.needs_details:
                # provide details
                src = src.with_details(dst.size, dst, self._codeloc())

            self.state.store_register(dst, src)
            if isinstance(stmt.src, (Expr.Register, Stmt.Call)):
                # set equivalence
                self.state.add_equivalence(self._codeloc(), dst, stmt.src)
            if isinstance(stmt.src, (Expr.Convert)) and isinstance(stmt.src.operand, Stmt.Call):
                # set equivalence
                self.state.add_equivalence(self._codeloc(), dst, stmt.src)

            self.state.register_expressions[(dst.reg_offset, dst.size)] = dst, stmt.src, self._codeloc()
        else:
            l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

    def _ail_handle_Store(self, stmt: Stmt.Store):

        self.state: 'PropagatorAILState'

        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)

        # is it accessing the stack?
        sp_offset = self.extract_offset_to_sp(addr.one_expr) if addr.one_expr is not None else None
        if sp_offset is not None:
            if isinstance(data.one_expr, Expr.StackBaseOffset):
                # convert it to a BV
                expr = data.one_expr
                data_v = self.sp_offset(data.one_expr.offset)
                size = data_v.size() // self.arch.byte_width
                to_store = PropValue.from_value_and_details(data_v, size, expr, self._codeloc())
            elif isinstance(data.value, claripy.ast.BV):
                expr = data.one_expr if data.one_expr is not None else stmt.data
                data_v = data.value
                size = data_v.size() // self.arch.byte_width
                to_store = PropValue.from_value_and_details(data_v, size, expr, self._codeloc())
            else:
                size = stmt.size
                to_store = data.with_details(stmt.size, data.one_expr if data.one_expr is not None else stmt.data,
                                             self._codeloc())

            # Storing data to a stack variable
            self.state.store_stack_variable(sp_offset, to_store, endness=stmt.endness)

            # set equivalence
            var = SimStackVariable(sp_offset, size)
            self.state.add_equivalence(self._codeloc(), var, stmt.data)

        else:
            addr_concrete = addr.one_expr
            if addr_concrete is None:
                # it can be a potential stack store with a variable offset
                self.state.last_stack_store = (self.block.addr, self.stmt_idx, stmt)
            else:
                self.state.global_stores.append((self.block.addr, self.stmt_idx, addr_concrete, stmt))
                if isinstance(addr_concrete, Expr.Const) and isinstance(stmt.size, int):
                    # set equivalence
                    var = SimMemoryVariable(addr_concrete.value, stmt.size)
                    self.state.add_equivalence(self._codeloc(), var, stmt.data)

    def _ail_handle_Jump(self, stmt):
        target = self._expr(stmt.target)
        if target is None or target.one_expr == stmt.target:
            return

        target_oneexpr = target.one_expr
        if target_oneexpr is not None and isinstance(target_oneexpr, Expr.Const):
            new_jump_stmt = Stmt.Jump(stmt.idx, target.one_expr, **stmt.tags)
            self.state.add_replacement(self._codeloc(),
                                       stmt,
                                       new_jump_stmt,
                                       )

    def _ail_handle_Call(self, expr_stmt: Stmt.Call):
        if isinstance(expr_stmt.target, Expr.Expression):
            _ = self._expr(expr_stmt.target)

        if expr_stmt.args:
            for arg in expr_stmt.args:
                _ = self._expr(arg)

        if expr_stmt.ret_expr is not None:
            if isinstance(expr_stmt.ret_expr, Expr.Register):
                # it has a return expression. awesome - treat it as an assignment

                # assume the return value always uses a full-width register
                # FIXME: Expose it as a configuration option
                return_value_use_full_width_reg = True
                if return_value_use_full_width_reg:
                    v = PropValue.from_value_and_details(
                        self.state.top(self.arch.bits), self.arch.bytes, expr_stmt.ret_expr, self._codeloc()
                    )
                    self.state.store_register(
                        Expr.Register(None, expr_stmt.ret_expr.variable, expr_stmt.ret_expr.reg_offset, self.arch.bits,
                                      reg_name=self.arch.translate_register_name(expr_stmt.ret_expr.reg_offset,
                                                                                 size=self.arch.bits)),
                        v
                    )
                else:
                    v = PropValue.from_value_and_details(
                        self.state.top(expr_stmt.ret_expr.size * self.arch.byte_width),
                        expr_stmt.ret_expr.size, expr_stmt.ret_expr, self._codeloc()
                    )
                    self.state.store_register(expr_stmt.ret_expr, v)
                # set equivalence
                self.state.add_equivalence(self._codeloc(), expr_stmt.ret_expr, expr_stmt)
            else:
                l.warning("Unsupported ret_expr type %s.", expr_stmt.ret_expr.__class__)

    def _ail_handle_ConditionalJump(self, stmt):
        _ = self._expr(stmt.condition)
        if stmt.true_target is not None:
            _ = self._expr(stmt.true_target)
        if stmt.false_target is not None:
            _ = self._expr(stmt.false_target)

    def _ail_handle_Return(self, stmt: Stmt.Return):
        if stmt.ret_exprs:
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)

    #
    # AIL expression handlers
    #

    # this method exists so that I can annotate the return type
    def _expr(self, expr) -> Optional[PropValue]:  # pylint:disable=useless-super-delegation
        return super()._expr(expr)

    def _ail_handle_Tmp(self, expr: Expr.Tmp) -> PropValue:
        tmp = self.state.load_tmp(expr.tmp_idx)

        if tmp is not None:
            # very first step - if we can get rid of this tmp and replace it with another, we should
            if expr.tmp_idx in self.state.temp_expressions:
                tmp_expr = self.state.temp_expressions[expr.tmp_idx]
                for _, (reg_atom, reg_expr, def_at) in self.state.register_expressions.items():
                    if reg_expr.likes(tmp_expr):
                        # make sure the register still holds the same value
                        current_reg_value = self.state.load_register(reg_atom)
                        if current_reg_value is not None:
                            if 0 in current_reg_value.offset_and_details:
                                detail = current_reg_value.offset_and_details[0]
                                if detail.def_at == def_at:
                                    l.debug("Add a replacement: %s with %s", expr, reg_atom)
                                    self.state.add_replacement(self._codeloc(), expr, reg_atom)
                                    top = self.state.top(expr.size * self.arch.byte_width)
                                    return PropValue.from_value_and_details(top, expr.size, expr, self._codeloc())

            # check if this new_expr uses any expression that has been overwritten
            all_subexprs = list(tmp.all_exprs())
            outdated = False
            for detail in tmp.offset_and_details.values():
                if detail.expr is None:
                    continue
                if self.is_using_outdated_def(detail.expr, detail.def_at, avoid=expr):
                    outdated = True
                    break

            if None in all_subexprs or outdated:
                top = self.state.top(expr.size * self.arch.byte_width)
                self.state.add_replacement(self._codeloc(), expr, top)
                return PropValue.from_value_and_details(top, expr.size, expr, self._codeloc())

            if len(all_subexprs) == 1 and 0 in tmp.offset_and_details and tmp.offset_and_details[0].size == expr.size:
                subexpr = all_subexprs[0]
                l.debug("Add a replacement: %s with %s", expr, subexpr)
                self.state.add_replacement(self._codeloc(), expr, subexpr)
            elif tmp.offset_and_details and 0 in tmp.offset_and_details:
                non_zero_subexprs = list(tmp.non_zero_exprs())
                if len(non_zero_subexprs) == 1 and non_zero_subexprs[0] is tmp.offset_and_details[0].expr:
                    # we will use the zero-extended version as the replacement
                    subexpr = non_zero_subexprs[0]
                    subexpr = PropValue.extend_ail_expression(expr.bits - subexpr.bits, subexpr)
                    l.debug("Add a replacement: %s with %s", expr, subexpr)
                    self.state.add_replacement(self._codeloc(), expr, subexpr)
            return tmp

        if not self._propagate_tmps:
            # we should not propagate any tmps. as a result, we return None for reading attempts to a tmp.
            return PropValue(self.state.top(expr.size * self.arch.byte_width))

        return PropValue(self.state.top(expr.size * self.arch.byte_width))

    def _ail_handle_Register(self, expr: Expr.Register) -> Optional[PropValue]:

        self.state: 'PropagatorAILState'

        # Special handling for SP and BP
        if self._stack_pointer_tracker is not None:
            if expr.reg_offset == self.arch.sp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.sp_offset)
                if sb_offset is not None:
                    new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                    self.state.add_replacement(self._codeloc(), expr, new_expr)
                    return PropValue.from_value_and_details(
                        self.sp_offset(sb_offset), expr.size, new_expr, self._codeloc()
                    )
            elif expr.reg_offset == self.arch.bp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.bp_offset)
                if sb_offset is not None:
                    new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                    self.state.add_replacement(self._codeloc(), expr, new_expr)
                    return PropValue.from_value_and_details(
                        self.sp_offset(sb_offset), expr.size, new_expr, self._codeloc()
                    )

        def _test_concatenation(pv: PropValue):
            if pv.offset_and_details is not None and len(pv.offset_and_details) == 2 and 0 in pv.offset_and_details:
                lo_value = pv.offset_and_details[0]
                hi_offset = next(iter(k for k in pv.offset_and_details if k != 0))
                hi_value = pv.offset_and_details[hi_offset]
                if lo_value.def_at == hi_value.def_at:
                    # it's the same value! we can apply concatenation here
                    if isinstance(hi_value.expr, Expr.Const) and hi_value.expr.value == 0:
                        # it's probably an up-cast
                        mappings = {
                            # (lo_value.size, hi_value.size): (from_bits, to_bits)
                            (1, 1): (8, 16),  # char to short
                            (1, 3): (8, 32),  # char to int
                            (1, 7): (8, 64),  # char to int64
                            (2, 2): (16, 32),  # short to int
                            (2, 6): (16, 64),  # short to int64
                            (4, 4): (32, 64),  # int to int64
                        }
                        key = (lo_value.size, hi_value.size)
                        if key in mappings:
                            from_bits, to_bits = mappings[key]
                            result_expr = Expr.Convert(None, from_bits, to_bits, False, lo_value.expr)
                            return True, result_expr
                    result_expr = Expr.BinaryOp(None, "Concat", [hi_value.expr, lo_value.expr], False)
                    return True, result_expr
            return False, None

        new_expr = self.state.load_register(expr)
        if new_expr is not None:
            # check if this new_expr uses any expression that has been overwritten
            replaced = False
            outdated = False
            all_subexprs = list(new_expr.all_exprs())
            for _, detail in new_expr.offset_and_details.items():
                if detail.expr is None:
                    break
                if self.is_using_outdated_def(detail.expr, detail.def_at, avoid=expr):
                    outdated = True
                    break

            if all_subexprs and None not in all_subexprs and not outdated:
                if len(all_subexprs) == 1:
                    # trivial case
                    subexpr = all_subexprs[0]
                    if subexpr.size == expr.size:
                        replaced = True
                        l.debug("Add a replacement: %s with %s", expr, subexpr)
                        self.state.add_replacement(self._codeloc(), expr, subexpr)
                else:
                    is_concatenation, result_expr = _test_concatenation(new_expr)
                    if is_concatenation:
                        replaced = True
                        l.debug("Add a replacement: %s with %s", expr, result_expr)
                        self.state.add_replacement(self._codeloc(), expr, result_expr)

            if not replaced:
                l.debug("Add a replacement: %s with TOP", expr)
                self.state.add_replacement(self._codeloc(), expr, self.state.top(expr.bits))
            else:
                return new_expr

        return PropValue.from_value_and_details(self.state.top(expr.bits), expr.size, expr, self._codeloc())

    def _ail_handle_Load(self, expr: Expr.Load) -> Optional[PropValue]:

        self.state: 'PropagatorAILState'

        addr = self._expr(expr.addr)

        addr_expr = addr.one_expr
        var_defat = None

        if addr_expr is not None:
            if isinstance(addr_expr, Expr.StackBaseOffset) and not isinstance(expr.addr, Expr.StackBaseOffset):
                l.debug("Add a replacement: %s with %s", expr.addr, addr_expr)
                self.state.add_replacement(self._codeloc(), expr.addr, addr_expr)

            sp_offset = self.extract_offset_to_sp(addr_expr)
            if sp_offset is not None:
                # Stack variable.
                var = self.state.load_stack_variable(sp_offset, expr.size, endness=expr.endness)
                if var is not None:
                    var_defat = var.one_defat
                    # We do not add replacements here since in AIL function and block simplifiers we explicitly forbid
                    # replacing stack variables, unless this is the parameter of a call (indicated by expr.func_arg is
                    # True).
                    if getattr(expr, "func_arg", False) is True \
                            or (self.state._gp is not None
                                and not self.state.is_top(var.value)
                                and var.value.concrete
                                and var.value._model_concrete.value == self.state._gp):
                        if var.one_expr is not None:
                            if not self.is_using_outdated_def(var.one_expr, var.one_defat, avoid=expr.addr):
                                l.debug("Add a replacement: %s with %s", expr, var.one_expr)
                                self.state.add_replacement(self._codeloc(), expr, var.one_expr)
                        else:
                            # there isn't a single expression to replace with. remove the old replacement for this
                            # expression if available.
                            self.state.add_replacement(self._codeloc(), expr, self.state.top(expr.bits))
                    if not self.state.is_top(var.value):
                        return var

        if addr_expr is not None and addr_expr is not expr.addr:
            new_expr = Expr.Load(expr.idx, addr_expr, expr.size, expr.endness, **expr.tags)
        else:
            new_expr = expr
        prop_value = PropValue.from_value_and_details(
            self.state.top(expr.size * self.arch.byte_width), expr.size, new_expr,
            self._codeloc() if var_defat is None else var_defat
        )
        return prop_value

    def _ail_handle_Convert(self, expr: Expr.Convert) -> PropValue:
        o_value = self._expr(expr.operand)

        if o_value is None or self.state.is_top(o_value.value):
            new_value = self.state.top(expr.to_bits)
        else:
            if expr.from_bits < expr.to_bits:
                if expr.is_signed:
                    new_value = claripy.SignExt(expr.to_bits - expr.from_bits, o_value.value)
                else:
                    new_value = claripy.ZeroExt(expr.to_bits - expr.from_bits, o_value.value)
            elif expr.from_bits > expr.to_bits:
                new_value = claripy.Extract(expr.to_bits - 1, 0, o_value.value)
            else:
                new_value = o_value.value

        o_expr = o_value.one_expr
        o_defat = o_value.one_defat
        if o_expr is not None:
            # easy cases
            if type(o_expr) is Expr.Convert:
                if expr.from_bits == o_expr.to_bits and expr.to_bits == o_expr.from_bits:
                    # eliminate the redundant Convert
                    new_expr = o_expr.operand
                else:
                    new_expr = Expr.Convert(expr.idx, o_expr.from_bits, expr.to_bits, expr.is_signed, o_expr.operand)
            elif type(o_expr) is Expr.Const:
                # do the conversion right away
                value = o_expr.value
                mask = (2 ** expr.to_bits) - 1
                value &= mask
                new_expr = Expr.Const(expr.idx, o_expr.variable, value, expr.to_bits)
            else:
                new_expr = Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, o_expr, **expr.tags)

            if isinstance(new_expr, Expr.Convert) and not new_expr.is_signed \
                    and new_expr.to_bits > new_expr.from_bits and new_expr.from_bits % self.arch.byte_width == 0:
                # special handling for zero-extension: it simplifies the code if we explicitly model zeros
                new_size = new_expr.from_bits // self.arch.byte_width
                offset_and_details = {
                    0: Detail(new_size, new_expr.operand, o_defat),
                    new_size: Detail(
                        new_expr.size - new_size,
                        Expr.Const(expr.idx, None, 0, new_expr.to_bits - new_expr.from_bits),
                        self._codeloc()),
                }
            else:
                offset_and_details = {0: Detail(expr.size, new_expr, self._codeloc())}

            return PropValue(new_value, offset_and_details=offset_and_details)

        elif o_value.offset_and_details:
            # hard cases... we will keep certain labels and eliminate other labels
            start_offset = 0
            end_offset = expr.to_bits // self.arch.byte_width  # end_offset is exclusive
            offset_and_details = {}
            max_offset = max(o_value.offset_and_details.keys())
            for offset_, detail_ in o_value.offset_and_details.items():
                if offset_ < start_offset < offset_ + detail_.size:
                    # we start here
                    off = 0
                    siz = min(end_offset, offset_ + detail_.size) - start_offset
                    expr_ = PropValue.extract_ail_expression(
                        (start_offset - offset_) * self.arch.byte_width,
                        siz * self.arch.byte_width,
                        detail_.expr
                    )
                    offset_and_details[off] = Detail(siz, expr_, detail_.def_at)
                elif offset_ >= start_offset and offset_ + detail_.size <= end_offset:
                    # we include the whole thing
                    off = offset_ - start_offset
                    siz = detail_.size
                    if off == max_offset and off + siz < end_offset:
                        # extend the expr
                        expr_ = PropValue.extend_ail_expression(
                            (end_offset - (off + siz)) * self.arch.byte_width,
                            detail_.expr
                        )
                        siz = end_offset - off
                    else:
                        expr_ = detail_.expr
                    offset_and_details[off] = Detail(siz, expr_, detail_.def_at)
                elif offset_ < end_offset <= offset_ + detail_.size:
                    # we include all the way until end_offset
                    if offset_ < start_offset:
                        off = 0
                        siz = end_offset - start_offset
                    else:
                        off = offset_ - start_offset
                        siz = end_offset - offset_
                    expr_ = PropValue.extract_ail_expression(0, siz * self.arch.byte_width, detail_.expr)
                    offset_and_details[off] = Detail(siz, expr_, detail_.def_at)

            return PropValue(
                new_value,
                offset_and_details=offset_and_details
            )
        else:
            # it's empty... no expression is available for whatever reason
            return PropValue.from_value_and_details(new_value, expr.size, expr, self._codeloc())

    def _ail_handle_Const(self, expr: Expr.Const) -> PropValue:
        return PropValue.from_value_and_details(claripy.BVV(expr.value, expr.bits), expr.size, expr, self._codeloc())

    def _ail_handle_DirtyExpression(self, expr: Expr.DirtyExpression) -> Optional[PropValue]:  # pylint:disable=no-self-use

        if isinstance(expr.dirty_expr, Expr.VEXCCallExpression):
            for operand in expr.dirty_expr.operands:
                _ = self._expr(operand)

        return PropValue.from_value_and_details(
            self.state.top(expr.bits), expr.size, expr, self._codeloc()
        )

    def _ail_handle_ITE(self, expr: Expr.ITE) -> Optional[PropValue]:
        # pylint:disable=unused-variable
        cond = self._expr(expr.cond)
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)

        return PropValue.from_value_and_details(
            self.state.top(expr.bits),
            expr.size, expr, self._codeloc()
        )

    def _ail_handle_Reinterpret(self, expr: Expr.Reinterpret) -> Optional[PropValue]:
        arg = self._expr(expr.operand)

        if self.state.is_top(arg.value):
            one_expr = arg.one_expr
            if one_expr is not None:
                expr = Expr.Reinterpret(expr.idx, expr.from_bits, expr.from_type, expr.to_bits, expr.to_type, one_expr,
                                        **expr.tags)

        return PropValue.from_value_and_details(
            arg.value,
            expr.size, expr, self._codeloc()
        )

    def _ail_handle_CallExpr(self, expr_stmt: Stmt.Call) -> Optional[PropValue]:
        if isinstance(expr_stmt.target, Expr.Expression):
            _ = self._expr(expr_stmt.target)

        if expr_stmt.args:
            for arg in expr_stmt.args:
                _ = self._expr(arg)

        # ignore ret_expr
        return PropValue.from_value_and_details(
            self.state.top(expr_stmt.bits),
            expr_stmt.size, expr_stmt, self._codeloc()
        )

    def _ail_handle_Not(self, expr):
        o_value = self._expr(expr.operand)

        value = self.state.top(expr.bits)
        if o_value is None:
            new_expr = expr
        else:
            o_expr = o_value.one_expr
            new_expr = Expr.UnaryOp(expr.idx,
                                    'Not',
                                     o_expr if o_expr is not None else expr.operands[0],
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Cmp(self, expr: Expr.BinaryOp) -> PropValue:
        operand_0_value = self._expr(expr.operands[0])
        operand_1_value = self._expr(expr.operands[1])

        if operand_0_value is not None and operand_1_value is not None:
            operand_0_oneexpr = operand_0_value.one_expr
            operand_1_oneexpr = operand_1_value.one_expr
            if operand_0_oneexpr is expr.operands[0] and operand_1_oneexpr is expr.operands[1]:
                # nothing changed
                return PropValue.from_value_and_details(self.state.top(expr.bits), expr.size, expr, self._codeloc())
            else:
                operand_0 = operand_0_oneexpr if operand_0_oneexpr is not None else expr.operands[0]
                operand_1 = operand_1_oneexpr if operand_1_oneexpr is not None else expr.operands[1]

            new_expr = Expr.BinaryOp(expr.idx, expr.op, [operand_0, operand_1], expr.signed, **expr.tags)
        else:
            new_expr = expr

        return PropValue.from_value_and_details(
            self.state.top(expr.bits),
            expr.size, new_expr, self._codeloc()
        )

    _ail_handle_CmpF = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpLEs = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLTs = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp
    _ail_handle_CmpGEs = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGTs = _ail_handle_Cmp
    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp

    def _ail_handle_Add(self, expr: Expr.BinaryOp) -> PropValue:
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        if o0_value is None or o1_value is None:
            new_expr = expr
            value = self.state.top(expr.bits)
        else:
            if o0_value.value.concrete and o1_value.value.concrete:
                value = o0_value.value + o1_value.value
            else:
                value = self.state.top(expr.bits)

            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            if isinstance(o0_expr, Expr.BasePointerOffset) and isinstance(o1_expr, Expr.Const):
                new_expr = o0_value.one_expr.copy()
                new_expr.offset += o1_expr.value
            else:
                new_expr = Expr.BinaryOp(expr.idx,
                                         'Add',
                                         [o0_expr if o0_expr is not None else expr.operands[0],
                                          o1_expr if o1_expr is not None else expr.operands[1],],
                                         expr.signed,
                                         **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Sub(self, expr: Expr.BinaryOp) -> PropValue:
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        if o0_value is None or o1_value is None:
            new_expr = expr
            value = self.state.top(expr.bits)
        else:
            if o0_value.value.concrete and o1_value.value.concrete:
                value = o0_value.value - o1_value.value
            else:
                value = self.state.top(expr.bits)

            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            if isinstance(o0_expr, Expr.BasePointerOffset) and isinstance(o1_expr, Expr.Const):
                new_expr = o0_value.one_expr.copy()
                new_expr.offset -= o1_expr.value
            else:
                new_expr = Expr.BinaryOp(expr.idx,
                                         'Sub',
                                         [o0_expr if o0_expr is not None else expr.operands[0],
                                          o1_expr if o1_expr is not None else expr.operands[1],],
                                         expr.signed,
                                         **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_StackBaseOffset(self, expr: Expr.StackBaseOffset) -> PropValue:  # pylint:disable=no-self-use
        return PropValue.from_value_and_details(self.state.top(expr.bits), expr.size, expr, self._codeloc())

    def _ail_handle_And(self, expr: Expr.BinaryOp):

        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr

            # Special logic for stack pointer alignment
            sp_offset = self.extract_offset_to_sp(o0_value.value)
            if sp_offset is not None and type(o1_expr) is Expr.Const and is_alignment_mask(o1_expr.value):
                value = o0_value.value
                new_expr = o0_expr
            elif isinstance(o0_expr, Expr.StackBaseOffset) and type(o1_expr) is Expr.Const \
                    and is_alignment_mask(o1_expr.value):
                value = o0_value.value
                new_expr = o0_expr
            else:
                value = self.state.top(expr.bits)
                new_expr = Expr.BinaryOp(expr.idx,
                                         'And',
                                         [o0_expr if o0_expr is not None else expr.operands[0],
                                          o1_expr if o1_expr is not None else expr.operands[1],],
                                         expr.signed,
                                         **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Or(self, expr: Expr.BinaryOp):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Or',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Xor(self, expr: Expr.BinaryOp):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Xor',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Shl(self, expr: Expr.BinaryOp):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Shl',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1], ],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Shr(self, expr: Expr.BinaryOp):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Shr',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Sar(self, expr: Expr.BinaryOp):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Sar',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Mul(self, expr):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Mul',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Mull(self, expr):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Mull',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Div(self, expr):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Div',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_DivMod(self, expr):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'DivMod',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1],],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    def _ail_handle_Concat(self, expr):
        o0_value = self._expr(expr.operands[0])
        o1_value = self._expr(expr.operands[1])

        value = self.state.top(expr.bits)
        if o0_value is None or o1_value is None:
            new_expr = expr
        else:
            o0_expr = o0_value.one_expr
            o1_expr = o1_value.one_expr
            new_expr = Expr.BinaryOp(expr.idx,
                                     'Concat',
                                     [o0_expr if o0_expr is not None else expr.operands[0],
                                      o1_expr if o1_expr is not None else expr.operands[1], ],
                                     expr.signed,
                                     **expr.tags)
        return PropValue.from_value_and_details(value, expr.size, new_expr, self._codeloc())

    #
    # Util methods
    #

    def is_using_outdated_def(self, expr: Expr.Expression, expr_defat: 'CodeLocation',
                              avoid: Optional[Expr.Expression]=None) -> bool:

        from .outdated_definition_walker import OutdatedDefinitionWalker  # pylint:disable=import-outside-toplevel

        walker = OutdatedDefinitionWalker(expr, expr_defat, self.state,
                                          avoid=avoid,
                                          extract_offset_to_sp=self.extract_offset_to_sp)
        walker.walk_expression(expr)
        return walker.out_dated
