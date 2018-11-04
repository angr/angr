from sys import maxsize
from itertools import chain, zip_longest, tee
from collections import defaultdict

from rdict import RangeDict, MeldDict

from ..misc.ux import deprecated
from ..misc.plugins import PluginHub, PluginPreset
from ..errors import AngrExitError

import logging
l = logging.getLogger(name=__name__)


class EngineRanges(MeldDict):

    def __init__(self):
        super(EngineRanges, self).__init__()

        # A set of all stop points that are introduced by the ranges.
        self._stop_points = set()

        # A mapping that stores engines along with a sets of stop points, that
        # should not affect those engines.
        self._amend_engines = defaultdict(set)

        # The reversed version of of self._amend_engines.
        self._reverse_amend = defaultdict(set)

    def list_stop_points(self, engine):
        """
        Return a set of all stop points at which the given engine should stop execution.

        :param engine:
        :return:
        """
        return self._stop_points - self._amend_engines.get(engine, set())

    def occupy(self, start, end, value, **meld_opts):
        return super(EngineRanges, self).occupy(start, end, value, **meld_opts)

    def _replace(self, left_idx, right_idx, items):
        # Normalize indexes.
        left_idx = max(left_idx, 0)
        right_idx = min(right_idx, len(self._list))

        # Remove old stop points that were created by those ranges.
        for item in self._list[left_idx:right_idx]:
            self._stop_points.discard(item.start)
            for engine in self._reverse_amend[item.start]:
                self._amend_engines[engine].discard(item.start)
            self._reverse_amend.pop(item.start)

        # Replace ranges.
        self._list[left_idx:right_idx] = items

        # Add new stop points per range.
        for item in items:
            self._stop_points.add(item.start)

            if item.value:
                engine = item.value[0]
                self._amend_engines[engine].add(item.start)
                self._reverse_amend[item.start].add(engine)

    def _meld(self, old_val, new_val, operation=None, **kwargs):
        if operation == 'insert':
            return new_val + old_val
        elif operation == 'append':
            return old_val + new_val
        elif operation == 'assign':
            return new_val
        else:
            raise ValueError(operation)


class EngineSelector(PluginHub):

    def __init__(self, project=None):
        super(EngineSelector, self).__init__()
        self.project = project

        self._eager_engines = []
        self._regular_engines = []
        self._fallback_engines = []

        self._default_engine = None
        self._procedure_engine = None

        self._assigned_engines = EngineRanges()

    def __getstate__(self):
        s = super(EngineSelector, self).__getstate__()
        return s, self._default_engine, self._procedure_engine, self.project, \
            self._eager_engines, self._regular_engines, self._fallback_engines, \
            self._assigned_engines

    def __setstate__(self, s):
        super(EngineSelector, self).__setstate__(s[0])
        self._default_engine, self._procedure_engine, self.project, \
            self._eager_engines, self._regular_engines, self._fallback_engines, \
            self._assigned_engines = s[1:]

    #
    #   ...
    #

    def _init_plugin(self, plugin_cls):
        return plugin_cls(self.project)

    def use_plugin_preset(self, preset, adjust_order=True, assign_engines=True):  # pylint:disable=arguments-differ
        super(EngineSelector, self).use_plugin_preset(preset)

        if adjust_order and self.plugin_preset.has_order():
            self._eager_engines = self.plugin_preset.eager_engines
            self._regular_engines = self.plugin_preset.regular_engines
            self._fallback_engines = self.plugin_preset.fallback_engines

        if assign_engines:
            self.assign_engines((0, maxsize), self._regular_engines)

        if self.plugin_preset.has_default_engine():
            self._default_engine = self.plugin_preset.default_engine

        if self.plugin_preset.has_procedure_engine():
            self._procedure_engine = self.plugin_preset.procedure_engine

    #
    #   ...
    #

    @property
    def eager_engines(self):
        """
        A list of engines that will be executed first for _any_ address,
        regardless of the current assignments.

        :return:
        """
        return self._eager_engines

    @eager_engines.setter
    def eager_engines(self, value):
        self._eager_engines = list(value)

    @property
    def fallback_engines(self):
        """
        A list of engines that will be executed last for _any_ address,
        regardless of the current assignments.

        :return:
        """
        return self._fallback_engines

    @fallback_engines.setter
    def fallback_engines(self, value):
        self._fallback_engines = list(value)

    @property
    def regular_engines(self):
        """
        A list of engines that will be executed after the ``eager_engines``,
        but before the ``fallback_engines``, if no assignments were made for
        the execution address.

        """
        return self._regular_engines

    @regular_engines.setter
    def regular_engines(self, value):
        self._regular_engines = list(value)

    @property
    def order(self):
        """
        A list of engines that will be executed in case no engines were assigned
        for execution.

        :return:
        """
        return self._eager_engines + self._regular_engines + self._fallback_engines

    @order.setter
    @deprecated('regular_engines')
    def order(self, value):
        self._regular_engines = list(value)

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

    def assign_engines(self, addr, engines):
        """
        Assign engines to be executed for the specified address (or memory range).
        This will replace any previously assigned engines with the new ones.

        :param addr:    An integer specifying the address or a tuple of (min_addr, max_addr)
                        specifying a memory range.
        :param engines: A list of engines to assign to the address.
        """
        engines = self._normalize_engines(engines)
        min_addr, max_addr = self._addr_to_range(addr)
        self._assigned_engines.occupy(min_addr, max_addr, engines, operation='assign')

    def insert_engine(self, addr, engine):
        """
        Assign the given engine to be executed first for the specified address.

        :param addr:    An integer specifying the address or a tuple of (min_addr, max_addr)
                        specifying a memory range.
        :param engine:  The engine to be inserted.
        :return:
        """
        engines = self._normalize_engines([engine])
        min_addr, max_addr = self._addr_to_range(addr)
        self._assigned_engines.occupy(min_addr, max_addr, engines, operation='insert')

    def append_engine(self, addr, engine):
        """
        Assign an engine to be executed last for the specified address.

        :param addr:    An integer specifying the address or a tuple of (min_addr, max_addr)
                        specifying a memory range.
        :param engine:  The engine to be appended.
        :return:
        """
        engines = self._normalize_engines([engine])
        min_addr, max_addr = self._addr_to_range(addr)
        self._assigned_engines.occupy(min_addr, max_addr, engines, operation='append')

    def remove_engine(self, addr, engine):
        """
        Remove the engine from the list of engines that are assigned to the given
        address (or memory range).

        :param addr:    An integer specifying the address or a tuple of (min_addr, max_addr)
                        specifying a memory range.
        :param engine:  The engine to be removed.
        :return:
        """
        min_addr, max_addr = self._addr_to_range(addr)
        for _range in self._assigned_engines.irange(min_addr, max_addr):
            del self._assigned_engines[_range.start:_range.end]

            new_engines = [e for e in _range.value if e is not engine]
            not new_engines or self._assigned_engines.occupy(_range.start, _range.end, new_engines)

    def list_engines(self, addr):
        """
        List all engines that are assigned to the given address.

        :param addr:    An integer specifying the address.
        :return:
        """
        return self._normalize_engines(self._assigned_engines.get(addr, []))

    def list_stop_points(self, engine):
        """
        Return a set of all stop points at which the given engine should stop execution.

        :param engine:  The engine for which to return a set of stop points.
        :return:
        """
        return self._assigned_engines.list_stop_points(engine)

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

        elif engines is not None:
            engines = self._normalize_engines(engines)

        elif state._ip.concrete:
            regular_engines = self._assigned_engines.get(state.addr, self._regular_engines)
            engines = self._normalize_engines(self._eager_engines + regular_engines + self._fallback_engines)

        if not engines:
            engines = self._normalize_engines(self.order)

        for engine in engines:
            if engine.check(state, **kwargs):
                base_stop_points = self.list_stop_points(engine)
                base_stop_points -= {state.addr} if state._ip.concrete else set()
                successors = engine.process(state, base_stop_points=base_stop_points, **kwargs)
                if successors.processed:
                    return successors

        raise AngrExitError("All engines failed to execute!")

    def _addr_to_range(self, addr):
        if isinstance(addr, int):
            min_addr, max_addr = addr, addr + 1
        elif isinstance(addr, tuple):
            min_addr, max_addr = addr
        else:
            raise TypeError
        return min_addr, max_addr

    def _normalize_engines(self, engines):
        return [self.get_plugin(e) if isinstance(e, str) else e for e in engines]


class EnginePreset(PluginPreset):
    """
    This represents a preset of engines for an engine hub.

    As was pointed out by @rhelmot (see https://github.com/angr/angr/pull/897), there's a lot of
    behavior in angr which very very specifically assumes that the first engines to be executed
    are the ``failure`` and the ``syscall`` engines. This plugin preset addresses the issue by
    allowing a user to specify a list of plugins that should be executed first using the
    ``eager_engines`` parameter. "Eager" engines will be checked first for _any_ address,
    regardless of the current assignments.

    If you want to use your custom preset with the angr's original analyses, you should
    specify the following eager engines: ``failure``, ``syscall``.
    """

    def __init__(self, eager_engines=None, fallback_engines=None):
        super(EnginePreset, self).__init__()

        self._eager_engines = eager_engines or []
        self._fallback_engines = fallback_engines or []
        self._regular_engines = []

        self._default_engine = None
        self._procedure_engine = None

    def activate(self, hub):
        for plugin_name in self.order:
            if plugin_name not in self._default_plugins:
                l.warning("%s doesn't provide a plugin for %s. Expect execution to fail.", self, plugin_name)

    #
    #   ...
    #

    @property
    def eager_engines(self):
        """
        A list of engines that will be executed first for _any_ address,
        regardless of the current assignments.

        This list should start with ``failure`` and ``syscall``, if you want to
        use this preset with the angr's original analyses.

        :return:
        """
        return self._eager_engines

    @property
    def fallback_engines(self):
        """
        A list of engines that will be executed last for _any_ address,
        regardless of the current assignments.

        :return:
        """
        return self._fallback_engines

    @property
    def regular_engines(self):
        """
        A list of engines that will be executed after the ``eager_engines``,
        but before the ``fallback_engines``, if no assignments were made for
        the execution address.

        VEX and Unicorn engines are common examples of a "regular" engine.

        :return:
        """
        return self._regular_engines

    @regular_engines.setter
    def regular_engines(self, value):
        self._regular_engines = list(value)

    @property
    def order(self):
        order = self._eager_engines + self._regular_engines + self._fallback_engines
        return order if order else self.list_default_plugins()

    @order.setter
    @deprecated('regular_engines')
    def order(self, value):
        self._regular_engines = list(value)

    def has_order(self):
        return any((self._eager_engines, self._regular_engines, self._fallback_engines))

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
        result._eager_engines = list(self._eager_engines)  # pylint:disable=protected-access
        result._fallback_engines = list(self._fallback_engines)  # pylint:disable=protected-access
        result._regular_engines = list(self._regular_engines)  # pylint:disable=protected-access
        result._default_engine = self._default_engine  # pylint:disable=protected-access
        result._procedure_engine = self._procedure_engine  # pylint:disable=protected-access
        return result


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)
