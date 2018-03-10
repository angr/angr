from ..misc.plugins import PluginHub, PluginPreset
from ..errors import AngrExitError, SimEngineError

class EngineHub(PluginHub):
    def __init__(self, project):
        super(EngineHub, self).__init__()
        self.project = project

    def _init_plugin(self, plugin):
        return plugin(self.project)

    def successors(self, state, addr=None, jumpkind=None, **kwargs):
        """
        Perform execution using any applicable engine. Enumerate the current engines and use the
        first one that works. Return a SimSuccessors object classifying the results of the run.

        :param state:           The state to analyze
        :param addr:            optional, an address to execute at instead of the state's ip
        :param jumpkind:        optional, the jumpkind of the previous exit
        :param inline:          This is an inline execution. Do not bother copying the state.

        Additional keyword arguments will be passed directly into each engine's process method.
        """
        if kwargs.get('insn_bytes', None) is not None and kwargs.get('insn_text', None) is not None:
            raise AngrError("You cannot provide both 'insn_bytes' and 'insn_text'!")
        insn_text = kwargs.get('insn_text', None)
        if insn_text is not None:
            kwargs['insn_bytes'] = self.project.arch.asm(insn_text,
                                                         addr=kwargs.get('addr', 0),
                                                         as_bytes=True,
                                                         thumb=kwargs.get('thumb', False))

        if addr is not None or jumpkind is not None:
            state = state.copy()
            if addr is not None:
                state.ip = addr
            if jumpkind is not None:
                state.history.jumpkind = jumpkind

        if not self.has_plugin_preset:
            raise SimEngineError("EngineHub preset must be present to choose execution...")

        for engine in self._choose_engine(state, **kwargs):
            r = engine.process(state, **kwargs)
            if r.processed:
                return r

        raise AngrExitError("All engines failed to execute!")

    def _choose_engine(self, state, **kwargs):
        if self.failure.check(state, **kwargs): yield self.failure
        if self.syscall.check(state, **kwargs): yield self.syscall
        if self.hook.check(state, **kwargs): yield self.hook
        for engine in self._active_preset.choose_engine(self, state, **kwargs):
            yield engine

class EnginePreset(PluginPreset):
    def __init__(self):
        super(EnginePreset, self).__init__()

        self._order = []

    def choose_engine(self, hub, state, **kwargs):
        for engine_name in self._order:
            engine = hub.get_plugin(engine_name)
            if engine.check(state, **kwargs):
                yield engine

    def set_order(self, order):
        self._order = list(order)

    def copy(self):
        out = EnginePreset()
        out.default_plugins = dict(self.default_plugins)
        out._order = list(self._order)
        return out
