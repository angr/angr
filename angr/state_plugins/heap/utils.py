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
        sols = solver.eval_upto(x, 2)
        if len(sols) > 1:
            return sym_handler(x)
        else:
            return sols[0]
    else:
        return solver.eval(x)
