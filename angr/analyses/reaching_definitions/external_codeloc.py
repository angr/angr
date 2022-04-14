
from ...code_location import CodeLocation


class ExternalCodeLocation(CodeLocation):

    __slots__ = ()

    def __init__(self):
        super(ExternalCodeLocation, self).__init__(0, 0)

    def __repr__(self):
        return "[External]"
