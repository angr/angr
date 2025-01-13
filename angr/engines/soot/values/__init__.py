from __future__ import annotations

from .local import SimSootValue_Local
from .paramref import SimSootValue_ParamRef
from .arrayref import SimSootValue_ArrayRef, SimSootValue_ArrayBaseRef
from .thisref import SimSootValue_ThisRef
from .staticfieldref import SimSootValue_StaticFieldRef
from .instancefieldref import SimSootValue_InstanceFieldRef
from .constants import SimSootValue_IntConstant
from .strref import SimSootValue_StringRef


def translate_value(value, state):
    value_name = value.__class__.__name__
    value_name = value_name.removeprefix("Soot")
    value_cls_name = "SimSootValue_" + value_name

    g = globals()
    if value_cls_name in g:
        value_cls = g[value_cls_name]
    else:
        return value

    return value_cls.from_sootvalue(value, state)


__all__ = (
    "SimSootValue_ArrayBaseRef",
    "SimSootValue_ArrayRef",
    "SimSootValue_InstanceFieldRef",
    "SimSootValue_IntConstant",
    "SimSootValue_Local",
    "SimSootValue_ParamRef",
    "SimSootValue_StaticFieldRef",
    "SimSootValue_StringRef",
    "SimSootValue_ThisRef",
    "translate_value",
)
