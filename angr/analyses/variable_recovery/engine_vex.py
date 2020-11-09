
import pyvex

from ...engines.light import SimEngineLightVEXMixin
from ..typehoon import typevars, typeconsts
from .engine_base import SimEngineVRBase, RichR


class SimEngineVRVEX(
    SimEngineLightVEXMixin,
    SimEngineVRBase,
):

    # Statement handlers

    def _handle_Put(self, stmt):
        offset = stmt.offset
        r = self._expr(stmt.data)
        size = stmt.data.result_size(self.tyenv) // 8

        if offset == self.arch.ip_offset:
            return
        self._assign_to_register(offset, r, size)

    def _handle_Store(self, stmt):
        addr_r = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        r = self._expr(stmt.data)

        self._store(addr_r, r, size, stmt=stmt)

    def _handle_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:

            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data = self._expr(stmt.data)
            self._store(addr, data, size, stmt=stmt)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load(addr, self.tyenv.sizeof(stmt.dst) // 8)
        elif guard is False:
            data = self._expr(stmt.alt)
            self.tmps[stmt.dst] = data
        else:
            self.tmps[stmt.dst] = None

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            data = self._load(addr, size)
            self.tmps[stmt.result] = data
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

            self._store(addr, storedata, size)
            self.tmps[stmt.result] = RichR(1)

    def _handle_NoOp(self, stmt):
        pass

    # Expression handlers

    def _expr(self, expr):
        """

        :param expr:
        :return:
        :rtype: RichR
        """

        expr = super()._expr(expr)
        if expr is None:
            return RichR(None)
        return expr

    def _handle_Get(self, expr):
        reg_offset = expr.offset
        reg_size = expr.result_size(self.tyenv) // 8

        return self._read_from_register(reg_offset, reg_size, expr=expr)

    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) // 8

        return self._load(addr, size)

    def _handle_CCall(self, expr):  # pylint:disable=useless-return
        # ccalls don't matter
        return None

    # Function handlers

    def _handle_function(self, func_addr):  # pylint:disable=unused-argument,no-self-use,useless-return
        return None

    def _handle_Const(self, expr):
        return RichR(expr.con.value, typevar=typeconsts.int_type(expr.con.size))

    def _handle_Add(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = expr.result_size(self.tyenv)
                mask = (1 << result_size) - 1
                return RichR((r0.data + r1.data) & mask,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            typevar = None
            if r0.typevar is not None and isinstance(r1.data, int):
                typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.AddN(r1.data))

            sum_ = None
            if r0.data is not None and r1.data is not None:
                sum_ = r0.data + r1.data

            return RichR(sum_,
                         typevar=typevar,
                         type_constraints={ typevars.Subtype(r0.typevar, r1.typevar) },
                         )
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Sub(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = expr.result_size(self.tyenv)
                mask = (1 << result_size) - 1
                return RichR((r0.data - r1.data) & mask,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            typevar = None
            if r0.typevar is not None and isinstance(r1.data, int):
                typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data))

            diff = None
            if r0.data is not None and r1.data is not None:
                diff = r0.data - r1.data

            return RichR(diff,
                         typevar=typevar,
                         )
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_And(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                return RichR(r0.data & r1.data)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data & r1.data
            return RichR(r)
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Xor(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                return RichR(r0.data ^ r1.data)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data ^ r1.data
            return RichR(r)
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Or(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                return RichR(r0.data | r1.data)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data | r1.data
            return RichR(r)
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Not(self, expr):
        arg = expr.args[0]
        r0 = self._expr(arg)

        try:
            result_size = expr.result_size(self.tyenv)
            mask = (1 << result_size) - 1
            if isinstance(r0.data, int):
                # constants
                return RichR((~r0.data) & mask)

            r = None
            if r0.data is not None:
                r = (~r0.data) & mask
            return RichR(r)
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Mul(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            result_size = expr.result_size(self.tyenv)
            mask = (1 << result_size) - 1
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                return RichR((r0.data * r1.data) & mask)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data * r1.data
                r &= mask
            return RichR(r)
        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Shr(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = expr.result_size(self.tyenv)
                return RichR(r0.data >> r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data >> r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Sar(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = expr.result_size(self.tyenv)
                return RichR(r0.data >> r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data >> r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_Shl(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            result_size = expr.result_size(self.tyenv)
            mask = (1 << result_size) - 1
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                return RichR((r0.data << r1.data) & mask,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data << r1.data
                r &= mask

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as e:
            self.l.warning(e)
            return RichR(None)

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data == expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data != expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data <= expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data < expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _handle_CmpGE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data >= expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _handle_CmpGT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.data is None or expr_1.data is None:
            return RichR(None)

        try:
            return RichR(expr_0.data > expr_1.data)
        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)
