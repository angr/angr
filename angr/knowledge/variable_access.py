

class VariableAccess(object):
    def __init__(self, variable, access_type, location):
        self.variable = variable
        self.access_type = access_type
        self.location = location

    def __repr__(self):
        return "%s %s @ %s" % (self.access_type, self.variable, self.location)
