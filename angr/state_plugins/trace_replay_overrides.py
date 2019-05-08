import functools
from .plugin import SimStatePlugin


# TODO: write testcases for this behavior
class TraceReplayOverrides(SimStatePlugin):
    def __init__(self, syscall_overrides=None, dirty_overrides=None):
        super(TraceReplayOverrides, self).__init__()
        self.dirty_overrides = dirty_overrides if dirty_overrides is not None else list()
        self.syscall_overrides = syscall_overrides if syscall_overrides is not None else list()

    @SimStatePlugin.memo
    def copy(self, memo):
        return TraceReplayOverrides(self.syscall_overrides, self.dirty_overrides)

    def override_for_dirtyhelper(self, name):
        for condition, override in self.dirty_overrides:
            if condition(self.state, name):
                return functools.partial(override, name)
        return None

    def override_for_syscall(self, name):
        for condition, override in self.syscall_overrides:
            if condition(self.state, name):
                return functools.partial(override, name)
        return None


from angr.sim_state import SimState

SimState.register_default('trace_replay_overrides', TraceReplayOverrides)
