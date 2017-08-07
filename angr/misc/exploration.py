from ..errors import SimError
from ..errors import AngrError

def condition_to_lambda(condition, default=False):
    """
    Translates an integer, set or list into a lambda that checks a state address against the given addresses, and the
    other ones from the same basic block
    :param condition:   An integer, set, or list to convert to a lambda.
    :param default:     The default return value of the lambda (in case condition is None). Default: false.
    :returns:           A lambda that takes a state and returns the set of addresses that it matched from the condition
    """
    if condition is None:
        condition_function = lambda p: default

    elif isinstance(condition, (int, long)):
        return condition_to_lambda((condition,))

    elif isinstance(condition, (tuple, set, list)):
        addrs = set(condition)
        def condition_function(p):
            if p.addr in addrs:
                # returning {p.addr} instead of True to properly handle find/avoid conflicts
                return {p.addr}

            try:
                # If the address is not in the set (which could mean it is
                # not at the top of a block), check directly in the blocks
                # (Blocks are repeatedly created for every check, but with
                # the IRSB cache in angr lifter it should be OK.)
                return addrs.intersection(set(p.project.factory.block(p.addr).instruction_addrs))
            except (AngrError, SimError):
                return False

    elif hasattr(condition, '__call__'):
        condition_function = condition

    else:
        raise AngrExplorationTechniqueError("ExplorationTechnique is unable to convert given type (%s) to a callable condition function." % condition.__class__)

    return condition_function
