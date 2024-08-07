class StructuringError(Exception):
    """
    These types of errors are fatal and prevent any future working from structuring in this pass
    """

    pass


class SAILRSemanticError(Exception):
    """
    These types of errors may not kill the entire analysis, but they do kill the current working round.
    """

    pass


class UnsupportedAILNodeError(SAILRSemanticError):
    pass
