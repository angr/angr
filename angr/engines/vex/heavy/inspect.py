from ..light import VEXMixin
from ....state_plugins import BP_BEFORE, BP_AFTER, NO_OVERRIDE

class SimInspectMixin(VEXMixin):
    # open question: what should be done about the BP_AFTER breakpoints in cases where the engine uses exceptional control flow?
    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=NO_OVERRIDE):
        self.state._inspect('dirty', when=BP_BEFORE, dirty_name=func_name, dirty_args=args, dirty_handler=func, dirty_result=NO_OVERRIDE)
        retval = self.state._inspect_getattr('dirty_result', NO_OVERRIDE)
        func = self.state._inspect_getattr('dirty_handler', func)
        args = self.state._inspect_getattr('dirty_args', args)

        if func is NO_OVERRIDE:
            func = None
        if retval is NO_OVERRIDE:
            retval = super()._perform_vex_stmt_Dirty_call(func_name, ty, args, func=func)

        self.state._inspect('dirty', when=BP_AFTER, dirty_result=retval)
        return self.state._inspect_getattr('dirty_result', retval)

    def _handle_vex_stmt_IMark(self, stmt):
        if self.stmt_idx != 0:
            self.state._inspect('instruction', BP_AFTER)
        super()._handle_vex_stmt_IMark(stmt)
        self.state._inspect('instruction', BP_BEFORE, instruction=stmt.addr + stmt.delta)

    def _handle_vex_expr(self, expr):
        self.state._inspect('expr', BP_BEFORE, expr=expr, expr_result=NO_OVERRIDE)
        expr_result = self.state._inspect_getattr('expr_result', NO_OVERRIDE)
        if expr_result is not NO_OVERRIDE:
            return expr_result
        return super()._handle_vex_expr(expr)

    def _instrument_vex_expr(self, result):
        result = super()._instrument_vex_expr(result)
        self.state._inspect('expr', BP_AFTER, expr_result=result)
        return self.state._inspect_getattr('expr_result', result)

    def _handle_vex_stmt(self, stmt):
        self.state._inspect('statement', BP_BEFORE, statement=self.stmt_idx)
        super()._handle_vex_stmt(stmt)
        self.state._inspect('statement', BP_AFTER)

    def handle_vex_block(self, irsb):
        self.state._inspect('irsb', BP_BEFORE, address=irsb.addr)
        super().handle_vex_block(irsb)
        self.state._inspect('instruction', BP_AFTER)
        self.state._inspect('irsb', BP_AFTER, address=irsb.addr)


