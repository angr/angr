from ailment.statement import Call


class RustCall(Call):
    def __init__(
        self,
        idx,
        target,
        calling_convention=None,
        prototype=None,
        args=None,
        ret_expr=None,
        fp_ret_expr=None,
        **kwargs,
    ):
        super().__init__(idx, target, calling_convention, prototype, args, ret_expr, fp_ret_expr, **kwargs)
