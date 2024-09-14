from __future__ import annotations


class SAILRSemanticError(Exception):
    """
    These types of errors may not kill the entire analysis, but they do kill the current working round.
    They are caused when some non-expected state happens, like a ConditionalJump that is not the last statement in a
    block.
    """


class UnsupportedAILNodeError(SAILRSemanticError):
    """
    These type of errors are raised when an AIL node is not supported by the current implementation.
    Most common with Switch heads.
    """
