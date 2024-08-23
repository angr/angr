from __future__ import annotations


def translate_value(value, state):
    value_name = value.__class__.__name__
    if value_name.startswith("Soot"):
        value_name = value_name[4:]
    value_cls_name = "SimSootValue_" + value_name

    g = globals()
    if value_cls_name in g:
        value_cls = g[value_cls_name]
    else:
        return value

    return value_cls.from_sootvalue(value, state)


from .local import SimSootValue_Local
from .paramref import SimSootValue_ParamRef
from .arrayref import SimSootValue_ArrayRef, SimSootValue_ArrayBaseRef
from .thisref import SimSootValue_ThisRef
from .staticfieldref import SimSootValue_StaticFieldRef
from .instancefieldref import SimSootValue_InstanceFieldRef
from .constants import SimSootValue_IntConstant
from .strref import SimSootValue_StringRef
