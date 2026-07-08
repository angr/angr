"""
Classes to structure the different types of <Tag>s that can be attached to <Definition>s.

- Tag
    - FunctionTag
        - ParameterTag
        - LocalVariableTag
        - ReturnValueTag
    - InitialValueTag
"""

from __future__ import annotations

import json

from angr.protos import key_defs_pb2
from angr.serializable import Serializable


class Tag(Serializable):
    """
    A tag for a Definition that can carry different kinds of metadata.
    """

    def __init__(self, metadata: object = None):
        self.metadata = metadata

    def __repr__(self):
        return f"<{self.__class__.__name__} {{Metadata: {self.metadata}}}>"

    @classmethod
    def _get_cmsg(cls):
        return key_defs_pb2.Tag()

    def serialize_to_cmessage(self):
        msg = key_defs_pb2.Tag(kind=_TAG_CLASS_TO_KIND[type(self)])
        # ``metadata`` is typed ``object``; serialization is restricted to values that round-trip through json.
        # Anything else surfaces as TypeError here rather than failing silently downstream.
        if self.metadata is not None:
            msg.metadata_json = json.dumps(self.metadata)
        if isinstance(self, FunctionTag) and self.function is not None:
            msg.function = self.function
        return msg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        subclass = _KIND_TO_TAG_CLASS[cmsg.kind]
        metadata = json.loads(cmsg.metadata_json) if cmsg.HasField("metadata_json") else None
        if issubclass(subclass, FunctionTag):
            function = cmsg.function if cmsg.HasField("function") else None
            return subclass(function=function, metadata=metadata)
        return subclass(metadata=metadata)


class FunctionTag(Tag):
    """
    A tag for a definition created (or used) in the context of a function.
    """

    def __init__(self, function: int | None = None, metadata: object = None):
        super().__init__(metadata)
        self.function = function

    def __repr__(self):
        if self.function:
            return f"<{self.__class__.__name__} {{Function: {self.function:#x}, Metadata:{self.metadata}}}>"
        return super().__repr__()


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
    A tag for a definition of a local variable of a function.
    """


class ReturnValueTag(FunctionTag):
    """
    A tag for a definition of a return value
    of a function.
    """


class InitialValueTag(Tag):
    """
    A tag for a definition of an initial value
    """


class UnknownSizeTag(Tag):
    """
    A tag for a definition of an initial value
    """


_TAG_CLASS_TO_KIND: dict[type[Tag], int] = {
    Tag: key_defs_pb2.TAG,
    FunctionTag: key_defs_pb2.FUNCTION_TAG,
    SideEffectTag: key_defs_pb2.SIDE_EFFECT_TAG,
    ParameterTag: key_defs_pb2.PARAMETER_TAG,
    LocalVariableTag: key_defs_pb2.LOCAL_VARIABLE_TAG,
    ReturnValueTag: key_defs_pb2.RETURN_VALUE_TAG,
    InitialValueTag: key_defs_pb2.INITIAL_VALUE_TAG,
    UnknownSizeTag: key_defs_pb2.UNKNOWN_SIZE_TAG,
}
_KIND_TO_TAG_CLASS: dict[int, type[Tag]] = {v: k for k, v in _TAG_CLASS_TO_KIND.items()}
