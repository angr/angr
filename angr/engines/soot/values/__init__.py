
def translate_value(value):
    value_name = value.__class__.__name__
    if value_name.startswith("Soot"): value_name = value_name[4:]
    value_cls_name = "SimSootValue_" + value_name

    g = globals()
    if value_cls_name in g:
        value_cls = g[value_cls_name]
    else:
        return value

    value_ = value_cls.from_sootvalue(value)
    return value_


from .local import SimSootValue_Local
from .paramref import SimSootValue_ParamRef
