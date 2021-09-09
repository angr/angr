# pylint:disable=arguments-differ
from typing import Optional, TYPE_CHECKING
import logging

import claripy
import ailment

from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...calling_conventions import SimRegArg
from ...sim_type import SimTypeFunction
from ...engines.light import SimEngineLightAILMixin
from ...errors import SimMemoryMissingError
from ..typehoon import typeconsts, typevars
from ..typehoon.lifter import TypeLifter
from .engine_base import SimEngineVRBase, RichR

if TYPE_CHECKING:
    from .variable_recovery_fast import VariableRecoveryFastState


l = logging.getLogger(name=__name__)


class SimEngineVRAIL(
    SimEngineLightAILMixin,
    SimEngineVRBase,
):
    state: 'VariableRecoveryFastState'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._reference_spoffset: bool = False

    # Statement handlers

    def _ail_handle_Assignment(self, stmt):
        dst_type = type(stmt.dst)

        if dst_type is ailment.Expr.Register:
            offset = stmt.dst.reg_offset
            data = self._expr(stmt.src)
            size = stmt.src.bits // 8

            self._assign_to_register(offset, data, size, src=stmt.src, dst=stmt.dst)

        elif dst_type is ailment.Expr.Tmp:
            # simply write to self.tmps
            data = self._expr(stmt.src)
            if data is None:
                return

            self.tmps[stmt.dst.tmp_idx] = data

        else:
            l.warning('Unsupported dst type %s.', dst_type)

    def _ail_handle_Store(self, stmt: ailment.Stmt.Store):
        addr_r = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        size = stmt.size
        self._store(addr_r, data, size, stmt=stmt)

    def _ail_handle_Jump(self, stmt):
        pass

    def _ail_handle_ConditionalJump(self, stmt):
        self._expr(stmt.condition)

    def _ail_handle_Call(self, stmt: ailment.Stmt.Call, is_expr=False) -> Optional[RichR]:
        target = stmt.target
        args = [ ]
        if stmt.args:
            for arg in stmt.args:
                self._reference_spoffset = True
                richr = self._expr(arg)
                self._reference_spoffset = False
                args.append(richr)

        ret_expr = None
        ret_reg_offset = None
        ret_val = None  # stores the value that this method should return to its caller when this is a call expression.
        if not is_expr:
            # this is a call statement. we need to update the return value register later
            ret_expr: Optional[ailment.Expr.Register] = stmt.ret_expr
            if ret_expr is not None:
                ret_reg_offset = ret_expr.reg_offset
            else:
                if stmt.calling_convention is not None:
                    # return value
                    ret_expr: SimRegArg = stmt.calling_convention.RETURN_VAL
                else:
                    l.debug("Unknown calling convention for function %s. Fall back to default calling convention.", target)
                    ret_expr: SimRegArg = self.project.factory.cc().RETURN_VAL

                if ret_expr is not None:
                    ret_reg_offset = self.project.arch.registers[ret_expr.reg_name][0]
        else:
            # this is a call expression. we just return the value at the end of this method
            pass

        # discover the prototype
        prototype: Optional[SimTypeFunction] = None
        if stmt.calling_convention is not None:
            prototype = stmt.calling_convention.func_ty
        elif isinstance(stmt.target, ailment.Expr.Const):
            func_addr = stmt.target.value
            if func_addr in self.kb.functions:
                func = self.kb.functions[func_addr]
                prototype = func.prototype

        # dump the type of the return value
        if prototype is not None:
            ret_ty = TypeLifter(self.arch.bits).lift(prototype.returnty)
        else:
            ret_ty = typevars.TypeVariable()
        if isinstance(ret_ty, typeconsts.BottomType):
            ret_ty = typevars.TypeVariable()

        if is_expr:
            # call expression mode
            ret_val = RichR(self.state.top(self.state.arch.bits), typevar=ret_ty)
        else:
            if ret_expr is not None:
                # update the return value register
                self._assign_to_register(
                    ret_reg_offset,
                    RichR(self.state.top(self.state.arch.bits), typevar=ret_ty),
                    self.state.arch.bytes,
                    dst=ret_expr,
                )

        if prototype is not None and args:
            # add type constraints
            for arg, arg_type in zip(args, prototype.args):
                if arg.typevar is not None:
                    arg_ty = TypeLifter(self.arch.bits).lift(arg_type)
                    type_constraint = typevars.Subtype(
                        arg_ty, arg.typevar
                    )
                    self.state.add_type_constraint(type_constraint)

        if is_expr:
            # call expression mode: return the actual return value
            return ret_val
        return None

    def _ail_handle_CallExpr(self, expr: ailment.Stmt.Call) -> RichR:
        return self._ail_handle_Call(expr, is_expr=True)

    def _ail_handle_Return(self, stmt: ailment.Stmt.Return):
        if stmt.ret_exprs:
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)

    # Expression handlers

    def _expr(self, expr: ailment.Expr.Expression):
        """

        :param expr:
        :return:
        :rtype: RichR
        """

        r = super()._expr(expr)
        if r is None:
            return RichR(self.state.top(expr.bits))
        return r

    def _ail_handle_BV(self, expr: claripy.ast.Base):
        return RichR(expr)

    def _ail_handle_Register(self, expr):
        offset = expr.reg_offset
        size = expr.bits // 8

        return self._read_from_register(offset, size, expr=expr)

    def _ail_handle_Load(self, expr):
        addr_r = self._expr(expr.addr)
        size = expr.size

        return self._load(addr_r, size, expr=expr)

    def _ail_handle_Const(self, expr):
        return RichR(claripy.BVV(expr.value, expr.size * self.state.arch.byte_width),
                     typevar=typeconsts.int_type(expr.size * self.state.arch.byte_width))

    def _ail_handle_BinaryOp(self, expr):
        r = super()._ail_handle_BinaryOp(expr)
        if r is None:
            # Treat it as a normal binaryop expression
            self._expr(expr.operands[0])
            self._expr(expr.operands[1])
            # still return a RichR instance
            r = RichR(self.state.top(expr.bits))
        return r

    def _ail_handle_Convert(self, expr: ailment.Expr.Convert):
        r = self._expr(expr.operand)
        typevar = None
        if r.typevar is not None:
            if isinstance(r.typevar, typevars.DerivedTypeVariable) and isinstance(r.typevar.label, typevars.ConvertTo):
                # there is already a conversion - overwrite it
                typevar = typevars.DerivedTypeVariable(r.typevar.type_var, typevars.ConvertTo(expr.to_bits))
            else:
                typevar = typevars.DerivedTypeVariable(r.typevar, typevars.ConvertTo(expr.to_bits))

        return RichR(self.state.top(expr.to_bits), typevar=typevar)

    def _ail_handle_Reinterpret(self, expr: ailment.Expr.Reinterpret):
        r = self._expr(expr.operand)
        typevar = None
        if r.typevar is not None:
            if isinstance(r.typevar, typevars.DerivedTypeVariable) and isinstance(r.typevar.label, typevars.ReinterpretAs):
                # there is already a reinterpretas - overwrite it
                typevar = typevars.DerivedTypeVariable(r.typevar.type_var, typevars.ReinterpretAs(expr.to_type, expr.to_bits))
            else:
                typevar = typevars.DerivedTypeVariable(r.typevar, typevars.ReinterpretAs(expr.to_type, expr.to_bits))

        return RichR(self.state.top(expr.to_bits), typevar=typevar)

    def _ail_handle_StackBaseOffset(self, expr: ailment.Expr.StackBaseOffset):
        try:
            values: MultiValues = self.state.stack_region.load(self.state.stack_addr_from_offset(expr.offset),
                                                               size=1,
                                                               endness=self.state.arch.memory_endness)
            vs = set()
            for v_set in values.values.values():
                vs.update(v_set)
        except SimMemoryMissingError:
            vs = None

        typevar_set = set()
        if vs:
            for value in vs:
                for _, v in self.state.extract_variables(value):
                    try:
                        typevar = self.state.typevars.get_type_variable(v, self._codeloc())
                        typevar_set.add(typevar)
                    except KeyError:
                        pass

        if not typevar_set:
            # allocate a new type variable
            typevar = typevars.TypeVariable()
        else:
            # TODO: Assign multiple typevars to the same typevar
            # FIXME
            typevar = next(iter(typevar_set))

        value_v = self.state.stack_address(expr.offset)
        richr = RichR(value_v, typevar=typevar)
        if self._reference_spoffset:
            self._reference(richr, self._codeloc(), src=expr)

        return richr

    def _ail_handle_ITE(self, expr: ailment.Expr.ITE):
        # pylint:disable=unused-variable
        cond = self._expr(expr.cond)
        r0 = self._expr(expr.iftrue)
        r1 = self._expr(expr.iffalse)

        return RichR(self.state.top(expr.bits))

    def _ail_handle_Cmp(self, expr):  # pylint:disable=useless-return
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        return RichR(self.state.top(1))

    _ail_handle_CmpF = _ail_handle_Cmp
    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp

    def _ail_handle_Add(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        type_constraints = set()
        if r0.typevar is not None and r1.data.concrete:
            # addition with constants. create a derived type variable
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.AddN(r1.data._model_concrete.value))
        else:
            # create a new type variable and add constraints accordingly
            typevar = typevars.TypeVariable()
            if r0.typevar is not None and r1.typevar is not None:
                type_constraints.add(typevars.Add(r0.typevar, r1.typevar, typevar))

        sum_ = None
        if r0.data is not None and r1.data is not None:
            sum_ = r0.data + r1.data

        if r0.typevar is not None and r1.typevar is not None:
            type_constraints.add(typevars.Subtype(r0.typevar, r1.typevar))

        return RichR(sum_,
                     typevar=typevar,
                     type_constraints=type_constraints,
                     )

    def _ail_handle_Sub(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        typevar = None
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data._model_concrete.value))

        sub = None
        if r0.data is not None and r1.data is not None:
            sub = r0.data - r1.data

        return RichR(sub,
                     typevar=typevar,
                     type_constraints={ typevars.Subtype(r0.typevar, r1.typevar) },
                     )

    def _ail_handle_Mul(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            result_size = arg0.bits
            return RichR(r0.data * r1.data,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(r,
                     typevar=r0.typevar,
                     )

    def _ail_handle_Mull(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            result_size = expr.bits
            if r0.data.size() < result_size:
                if expr.signed:
                    r0.data = claripy.SignExt(result_size - r0.data.size(), r0.data)
                else:
                    r0.data = claripy.ZeroExt(result_size - r0.data.size(), r0.data)
            if r1.data.size() < result_size:
                if expr.signed:
                    r1.data = claripy.SignExt(result_size - r1.data.size(), r1.data)
                else:
                    r1.data = claripy.ZeroExt(result_size - r1.data.size(), r1.data)
            return RichR(r0.data * r1.data,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(r,
                     typevar=r0.typevar,  # FIXME: the size is probably changed
                     )

    def _ail_handle_Div(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        from_size = expr.bits
        to_size = r1.bits

        if expr.signed:
            remainder = r0.data.SMod(claripy.SignExt(from_size - to_size, r1.data))
        else:
            remainder = r0.data % claripy.ZeroExt(from_size - to_size, r1.data)

        return RichR(remainder,
                     # typevar=r0.typevar,  # FIXME: Handle typevars for Div
                     )

    def _ail_handle_DivMod(self, expr: ailment.Expr.BinaryOp):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        from_size = expr.bits
        to_size = r1.bits

        if expr.signed:
            quotient = r0.data.SDiv(claripy.SignExt(from_size - to_size, r1.data))
            remainder = r0.data.SMod(claripy.SignExt(from_size - to_size, r1.data))
            quotient_size = to_size
            remainder_size = to_size
            r = claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder),
                claripy.Extract(quotient_size - 1, 0, quotient)
            )
        else:
            quotient = (r0.data // claripy.ZeroExt(from_size - to_size, r1.data))
            remainder = (r0.data % claripy.ZeroExt(from_size - to_size, r1.data))
            quotient_size = to_size
            remainder_size = to_size
            r = claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder),
                claripy.Extract(quotient_size - 1, 0, quotient)
            )

        return RichR(r,
                     # typevar=r0.typevar,  # FIXME: Handle typevars for DivMod
                     )

    def _ail_handle_Xor(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            result_size = arg0.bits
            return RichR(r0.data ^ r1.data,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(r,
                     typevar=r0.typevar,
                     )

    def _ail_handle_Shl(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(r,
                         typevar=r0.typevar,
                         )

        shiftamount = r1.data._model_concrete.value

        return RichR(r0.data << shiftamount,
                     typevar=typeconsts.int_type(result_size),
                     type_constraints=None)

    def _ail_handle_Shr(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(r,
                         typevar=r0.typevar,
                         )

        shiftamount = r1.data._model_concrete.value

        return RichR(claripy.LShR(r0.data, shiftamount),
                     typevar=typeconsts.int_type(result_size),
                     type_constraints=None)

    def _ail_handle_Sal(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(r,
                         typevar=r0.typevar,
                         )

        shiftamount = r1.data._model_concrete.value

        return RichR(r0.data << shiftamount,
                     typevar=typeconsts.int_type(result_size),
                     type_constraints=None)

    def _ail_handle_Sar(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(r,
                         typevar=r0.typevar,
                         )

        shiftamount = r1.data._model_concrete.value

        return RichR(r0.data >> shiftamount,
                     typevar=typeconsts.int_type(result_size),
                     type_constraints=None)

    def _ail_handle_And(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        if r0.data.concrete and r1.data.concrete:
            result_size = arg0.bits
            return RichR(
                r0.data & r1.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(expr.bits)
        return RichR(r, typevar=r0.typevar)

    def _ail_handle_Or(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        if r0.data.concrete and r1.data.concrete:
            result_size = arg0.bits
            return RichR(
                r0.data | r1.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(expr.bits)
        return RichR(r, typevar=r0.typevar)

    def _ail_handle_Concat(self, expr):

        arg0, arg1 = expr.operands

        _ = self._expr(arg0)
        _ = self._expr(arg1)

        # TODO: Model the operation. Don't lose type constraints
        return RichR(self.state.top(expr.bits))

    def _ail_handle_Not(self, expr):
        arg = expr.operands[0]
        expr = self._expr(arg)


        result_size = arg.bits

        if expr.data.concrete:
            return RichR(
                ~expr.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(r, typevar=expr.typevar)
