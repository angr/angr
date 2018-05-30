from ..misc.plugins import PluginHub, PluginPreset
from ..errors import AngrExitError

import logging
l = logging.getLogger(name=__name__)


class EngineHub(PluginHub):

    def __init__(self, project):
        super(EngineHub, self).__init__()
        self.project = project

        self._order = None
        self._default_engine = None
        self._procedure_engine = None

    def __getstate__(self):
        s = super(EngineHub, self).__getstate__()
        return s, self._order, self._default_engine, self._procedure_engine, self.project

    def __setstate__(self, s):
        super(EngineHub, self).__setstate__(s[0])
        self._order, self._default_engine, self._procedure_engine, self.project = s[1:]

    #
    #   ...
    #

    def _init_plugin(self, plugin_cls):
        return plugin_cls(self.project)

    def use_plugin_preset(self, preset, adjust_order=True):  # pylint:disable=arguments-differ
        super(EngineHub, self).use_plugin_preset(preset)

        if adjust_order and self.plugin_preset.has_order():
            self.order = self.plugin_preset.order

        if self.plugin_preset.has_default_engine():
            self.default_engine = self.plugin_preset.default_engine

        if self.plugin_preset.has_procedure_engine():
            self.procedure_engine = self.plugin_preset.procedure_engine

    #
    #   ...
    #

    @property
    def order(self):
        if self._order is None:
            if self.has_plugin_preset:
                self._order = self.plugin_preset.list_default_plugins()
            else:
                self._order = self._active_plugins.keys()
        return self._order

    @order.setter
    def order(self, value):
        self._order = list(value)

    @property
    def default_engine(self):
        if self.has_default_engine():
            return self.get_plugin(self._default_engine)
        return None

    @default_engine.setter
    def default_engine(self, value):
        self._default_engine = value

    def has_default_engine(self):
        return self._default_engine is not None

    @property
    def procedure_engine(self):
        if self.has_procedure_engine():
            return self.get_plugin(self._procedure_engine)
        return None

    @procedure_engine.setter
    def procedure_engine(self, value):
        self._procedure_engine = value

    def has_procedure_engine(self):
        return self._procedure_engine is not None

    #
    #   ...
    #

    def successors(self, state, addr=None, jumpkind=None, default_engine=False, procedure_engine=False,
                   engines=None, **kwargs):
        """
        Perform execution using any applicable engine. Enumerate the current engines and use the
        first one that works. Engines are enumerated in order, specified by the ``order`` attribute.

        :param state:               The state to analyze
        :param addr:                optional, an address to execute at instead of the state's ip
        :param jumpkind:            optional, the jumpkind of the previous exit
        :param default_engine:      Whether we should only attempt to use the default engine (usually VEX)
        :param procedure_engine:    Whether we should only attempt to use the procedure engine
        :param engines:             A list of engines to try to use, instead of the default.
                                    This list is expected to contain engine names or engine instances.

        Additional keyword arguments will be passed directly into each engine's process method.

        :return SimSuccessors:      A SimSuccessors object classifying the results of the run.
        """
        if addr is not None or jumpkind is not None:
            state = state.copy()
            if addr is not None:
                state.ip = addr
            if jumpkind is not None:
                state.history.jumpkind = jumpkind

        if default_engine and self.has_default_engine():
            engines = [self.default_engine]
        elif procedure_engine and self.has_procedure_engine():
            engines = [self.procedure_engine]
        elif engines is None:
            engines = (self.get_plugin(name) for name in self.order)
        else:
            engines = (self.get_plugin(e) if isinstance(e, str) else e for e in engines)

        for engine in engines:
            if engine.check(state, **kwargs):
                r = engine.process(state, **kwargs)
                if r.processed:
                    return r

        raise AngrExitError("All engines failed to execute!")


class EnginePreset(PluginPreset):
    """
    This represents a preset of engines for an engine hub.

    As was pointed out by @rhelmot (see https://github.com/angr/angr/pull/897), there's a lot of
    behavior in angr which very very specifically assumes that failure/syscall/hook will happen
    exactly the way we want them to.  This plugin preset addresses the issue by allowing a user to
    specify a list of plugins that should be executed first using the ``predefined_order``
    parameter. In that case, any other adjustment to order will be made with respect to the
    specified predefined order.

    If you want to use your custom preset with the angr's original analyses, you should
    specify the following predefined order: ``failure``, ``syscall``, and then ``hook``.
    """

    def __init__(self, predefined_order=None):
        super(EnginePreset, self).__init__()

        self._order = predefined_order
        self._predefined_order = predefined_order or []

        self._default_engine = None
        self._procedure_engine = None

    def activate(self, hub):
        for plugin_name in self._order:
            if plugin_name not in self._default_plugins:
                l.warn("%s doesn't provide a plugin for %s. Expect execution to fail.",
                       self, plugin_name)

    #
    #   ...
    #

    @property
    def order(self):
        if self._order is None:
            return self.list_default_plugins()
        return self._order

    @order.setter
    def order(self, value):
        self._order = self._predefined_order + list(value)

    def has_order(self):
        return self._order is not None

    @property
    def default_engine(self):
        return self._default_engine

    @default_engine.setter
    def default_engine(self, value):
        if value not in self.list_default_plugins():
            raise ValueError("%s not in list of default plugins")
        self._default_engine = value

    def has_default_engine(self):
        return self._default_engine is not None

    @property
    def procedure_engine(self):
        return self._procedure_engine

    @procedure_engine.setter
    def procedure_engine(self, value):
        if value not in self.list_default_plugins():
            raise ValueError("%s not in list of default plugins")
        self._procedure_engine = value

    def has_procedure_engine(self):
        return self._procedure_engine is not None

    def copy(self):
        result = super(EnginePreset, self).copy()
        result._predefined_order = list(self._predefined_order)  # pylint:disable=protected-access
        result._order = list(self._order)  # pylint:disable=protected-access
        result._default_engine = self._default_engine  # pylint:disable=protected-access
        result._procedure_engine = self._procedure_engine  # pylint:disable=protected-access
        return result
