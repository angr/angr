from .. import engines
from ..errors import SimError, AngrError, AngrExplorationTechniqueError


def condition_to_lambda(condition, default=False):
    """
    Translates an integer, set, list or function into a lambda that checks if state's current basic block matches
    some condition.

    :param condition:   An integer, set, list or lambda to convert to a lambda.
    :param default:     The default return value of the lambda (in case condition is None). Default: false.

    :returns:           A tuple of two items: a lambda that takes a state and returns the set of addresses that it
                        matched from the condition, and a set that contains the normalized set of addresses to stop
                        at, or None if no addresses were provided statically.
    """
    if condition is None:
        condition_function = lambda state: default
        static_addrs = set()

    elif isinstance(condition, int):
        return condition_to_lambda((condition,))

    elif isinstance(condition, (tuple, set, list)):
        static_addrs = set(condition)
        def condition_function(state):
            if state.addr in static_addrs:
                # returning {state.addr} instead of True to properly handle find/avoid conflicts
                return {state.addr}

            if not isinstance(state.project.factory.default_engine, engines.vex.VEXLifter):
                return False

            try:
                # If the address is not in the set (which could mean it is
                # not at the top of a block), check directly in the blocks
                # (Blocks are repeatedly created for every check, but with
                # the IRSB cache in angr lifter it should be OK.)
                return static_addrs.intersection(set(state.block().instruction_addrs))
            except (AngrError, SimError):
                return False

    elif hasattr(condition, '__call__'):
        condition_function = condition
        static_addrs = None
    else:
        raise AngrExplorationTechniqueError("ExplorationTechnique is unable to convert given type (%s) to a callable condition function." % condition.__class__)

    return condition_function, static_addrs
