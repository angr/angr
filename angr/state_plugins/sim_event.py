from __future__ import annotations
import traceback
import itertools

event_id_count = itertools.count()


class SimEvent:
    """
    A SimEvent is a log entry for some notable event during symbolic execution. It logs the location it was generated
    (ins_addr, bbl_addr, stmt_idx, and sim_procedure) as well as arbitrary tags (objects).

    You may also be interested in SimAction, which is a specialization of SimEvent for CPU events.
    """

    # def __init__(self, address=None, stmt_idx=None, message=None, exception=None, traceback=None):
    def __init__(self, state, event_type, **kwargs):
        self.id = next(event_id_count)
        self.type = event_type
        self.ins_addr = state.scratch.ins_addr
        self.bbl_addr = state.scratch.bbl_addr
        self.stmt_idx = state.scratch.stmt_idx
        self.sim_procedure = None if state.scratch.sim_procedure is None else state.scratch.sim_procedure.canonical
        self.objects = dict(kwargs)
        self.arch = state.arch

    def __repr__(self):
        return "<SimEvent %s %d, with fields %s>" % (self.type, self.id, ", ".join(self.objects.keys()))

    def _copy_event(self):
        c = self.__class__.__new__(self.__class__)
        c.id = self.id
        c.type = self.type
        c.bbl_addr = self.bbl_addr
        c.stmt_idx = self.stmt_idx
        c.sim_procedure = self.sim_procedure
        c.objects = dict(self.objects)

        return c


def resource_event(state, exception):
    for frame, lineno in reversed(list(traceback.walk_tb(exception.__traceback__))):
        module = frame.f_globals.get("__name__", "").split(".")
        function = frame.f_code.co_name
        if module[0] == "claripy" or module in (
            ["angr", "state_plugins", "solver"],
            ["angr", "state_plugins", "sim_action_object"],
        ):
            continue
        state.history.add_event(
            "insufficient_resources",
            module=module,
            function=function,
            lineno=lineno,
            type=type(exception),
            reason=exception.args,
        )
        break
