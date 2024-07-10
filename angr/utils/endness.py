from ailment.expression import Const


def ail_const_to_be(expr: Const, endness: str) -> Const:
    if endness == "Iend_LE" and expr.size > 1:
        # reverse the expression
        v = expr.value
        lst = []
        while len(lst) < expr.size:
            lst.append(v & 0xFF)
            v >>= 8
        v = 0
        for elem in lst:
            v <<= 8
            v += elem
        return Const(expr.idx, None, v, expr.bits, **expr.tags)
    return expr
