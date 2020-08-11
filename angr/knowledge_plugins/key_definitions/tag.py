class Tag:
    """
    A tag for a Definition that can carry different kinds of metadata.
    """
    def __init__(self, metadata: object=None):
        self.metadata = metadata

    def __repr__(self):
        return "<%s {Metadata: %s}>" % (self.__class__.__name__, self.metadata)


class ParameterTag(Tag):
    """
    A tag for a definition of a parameter.
    """

class ReturnValueTag(Tag):
    """
    A tag for a definiton of a return value
    of a function.
    """

class InitialValueTag(Tag):
    """
    A tag for a definiton of an initial value
    """
