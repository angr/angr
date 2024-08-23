from __future__ import annotations
from ...errors import SimSolverError


def concretize(x, solver, sym_handler):
    """
    For now a lot of naive concretization is done when handling heap metadata to keep things manageable. This idiom
    showed up a lot as a result, so to reduce code repetition this function uses a callback to handle the one or two
    operations that varied across invocations.

    :param x: the item to be concretized
    :param solver: the solver to evaluate the item with
    :param sym_handler: the handler to be used when the item may take on more than one value
    :returns: a concrete value for the item
    """
    if solver.symbolic(x):
        try:
            return solver.eval_one(x)
        except SimSolverError:
            return sym_handler(x)
    else:
        return solver.eval(x)
