#
# Exceptions
#

class BinaryError(Exception):
    pass


class InstructionError(BinaryError):
    pass


class ReassemblerFailureNotice(BinaryError):
    pass
