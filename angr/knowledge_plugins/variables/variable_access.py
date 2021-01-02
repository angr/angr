from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.code_location import CodeLocation


class VariableAccess:

    __slots__ = ('variable', 'access_type', 'location', )

    def __init__(self, variable, access_type, location):
        self.variable = variable
        self.access_type = access_type
        self.location: 'CodeLocation' = location

    def __repr__(self):
        return "%s %s @ %s" % (self.access_type, self.variable, self.location)

    def __eq__(self, other):
        return type(other) is VariableAccess and \
            self.variable == other.variable and \
            self.access_type == other.access_type and \
            self.location == other.location

    def __hash__(self):
        return hash((VariableAccess, self.variable, self.access_type, self.location))
