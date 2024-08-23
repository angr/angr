from __future__ import annotations


class BlockTerminationNotice(Exception):
    pass


class IncorrectLocationException(Exception):
    pass


class SootMethodNotLoadedException(Exception):
    pass


class SootFieldNotLoadedException(Exception):
    pass
