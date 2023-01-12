import sys

from .cfg_fast import CFGFast


class OutdatedError(Exception):
    pass


class CFG(CFGFast):  # pylint: disable=abstract-method
    """
    tl;dr: CFG is just a wrapper around CFGFast for compatibility issues. It will be fully replaced by CFGFast in future
    releases. Feel free to use CFG if you intend to use CFGFast. Please use CFGEmulated if you *have to* use the old,
    slow, dynamically-generated version of CFG.

    For multiple historical reasons, angr's CFG is accurate but slow, which does not meet what most people expect. We
    developed CFGFast for light-speed CFG recovery, and renamed the old CFG class to CFGEmulated. For compability
    concerns, CFG was kept as an alias to CFGEmulated.

    However, so many new users of angr would load up a binary and generate a CFG immediately after running
    "pip install angr", and draw the conclusion that "angr's CFG is so slow - angr must be unusable!" Therefore, we made
    the hard decision: CFG will be an alias to CFGFast, instead of CFGEmulated.

    To ease the transition of your existing code and script, the following changes are made:

    - A CFG class, which is a sub class of CFGFast, is created.
    - You will see both a warning message printed out to stderr and an exception raised by angr if you are passing CFG
      any parameter that only CFGEmulated supports. This exception is not a sub class of AngrError, so you wouldn't
      capture it with your old code by mistake.
    - In the near future, this wrapper class will be removed completely, and CFG will be a simple alias to CFGFast.

    We expect most interfaces are the same between CFGFast and CFGEmulated. Apparently some functionalities (like
    context-sensitivity, and state keeping) only exist in CFGEmulated, which is when you want to use CFGEmulated
    instead.
    """

    def __init__(self, **kwargs):
        outdated_exception = "CFG is now an alias to CFGFast."
        outdated_message = (
            "CFG is now an alias to CFGFast. Please switch to CFGEmulated if you need functionalities "
            'that only exist there. For most cases, your code should be fine by changing "CFG(...)" '
            'to "CFGEmulated(...)". Sorry for breaking your code with this giant change.'
        )

        cfgemulated_params = {
            "context_sensitivity_level",
            "avoid_runs",
            "enable_function_hints",
            "call_depth",
            "call_tracing_filter",
            "initial_state",
            "starts",
            "keep_state",
            "enable_advanced_backward_slicing",
            "enable_symbolic_back_traversal",
            "additional_edges",
            "no_construct",
        }

        # Sanity check to make sure the user only wants to use CFGFast

        for p in cfgemulated_params:
            if kwargs.get(p, None) is not None:
                sys.stderr.write(outdated_message + "\n")
                raise OutdatedError(outdated_exception)

        # Now initializes CFGFast :-)
        CFGFast.__init__(self, **kwargs)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("CFG", CFG)
