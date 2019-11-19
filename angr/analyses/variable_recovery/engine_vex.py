
from ...engines.light import SimEngineLightVEXMixin
from ...sim_variable import SimVariable
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

    def _handle_CCall(self, expr):
        # ccalls don't matter
        return None

    # Function handlers

    def _handle_function(self, func_addr):  # pylint:disable=unused-argument,no-self-use
        # TODO: Adjust the stack pointer
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
