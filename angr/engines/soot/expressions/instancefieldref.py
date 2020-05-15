
from .base import SimSootExpr
from ..values.local import SimSootValue_Local
from .... import sim_options as options


class SimSootExpr_InstanceFieldRef(SimSootExpr):
    def _execute(self):
        field_ref = self._translate_value(self.expr)
        this_ref = self.state.javavm_memory.load(SimSootValue_Local.from_sootvalue(self.expr.base, self.state))

        if options.JAVA_TRACK_ATTRIBUTES in self.state.options:
            this_ref.attributes.add((field_ref.field_name, field_ref.type))

        self.expr = self.state.javavm_memory.load(field_ref, none_if_missing=True)
