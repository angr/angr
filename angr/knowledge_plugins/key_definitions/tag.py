"""
Classes to structure the different types of <Tag>s that can be attached to <Definition>s.

- Tag
    - FunctionTag
        - ParameterTag
        - LocalVariableTag
        - ReturnValueTag
    - InitialValueTag
"""

class Tag:
    """
    A tag for a Definition that can carry different kinds of metadata.
    """
    def __init__(self, metadata: object=None):
        self.metadata = metadata

    def __repr__(self):
        return "<%s {Metadata: %s}>" % (self.__class__.__name__, self.metadata)

class FunctionTag(Tag):
    """
    A tag for a definition created (or used) in the context of a function.
    """

    def __init__(self, function: int=None, metadata: object=None):
        super(FunctionTag, self).__init__(metadata)
        self.function = function

    def __repr__(self):
        if self.function:
            return '<%s {Function: %#x, Metadata:%s}>' % (self.__class__.__name__, self.function, self.metadata)
        else:
            return super(FunctionTag, self).__repr__()


class SideEffectTag(FunctionTag):
    """
    A tag for a definition created or used as a side-effect of a function.

    Example: The <MemoryLocation> pointed by `rdi` during a `sprintf`.
    """


class ParameterTag(FunctionTag):
    """
    A tag for a definition of a parameter.
    """

class LocalVariableTag(FunctionTag):
    """
    A tag for a definiton of a local variable of a function.
    """

class ReturnValueTag(FunctionTag):
    """
    A tag for a definiton of a return value
    of a function.
    """

class InitialValueTag(Tag):
    """
    A tag for a definiton of an initial value
    """

class UnknownSizeTag(Tag):
    """
    A tag for a definiton of an initial value
    """
