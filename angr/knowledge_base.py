"""Representing the artifacts of a project."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from itertools import count
from typing import TYPE_CHECKING

from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from angr.knowledge_plugins.obfuscations import Obfuscations

from .knowledge_plugins.plugin import KnowledgeBasePlugin, default_plugins

if TYPE_CHECKING:
    from .knowledge_plugins import (
        Bookmarks,
        CFGManager,
        Comments,
        Function,
        FunctionManager,
        KeyDefinitionManager,
        PropagationManager,
        RuntimeDb,
        StructuredCodeManager,
        TypesStore,
        VariableManager,
        XRefManager,
    )
    from .project import Project


l = logging.getLogger(name=__name__)


kb_ctr = count(0, 1)


class KnowledgeBase:
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """

    functions: FunctionManager
    comments: Comments
    bookmarks: Bookmarks
    variables: VariableManager
    defs: KeyDefinitionManager
    cfgs: CFGManager
    _project: Project
    types: TypesStore
    propagations: PropagationManager
    xrefs: XRefManager
    decompilations: StructuredCodeManager
    obfuscations: Obfuscations
    rtdb: RuntimeDb

    def __init__(self, project, obj=None, name=None):
        if obj is not None:
            l.warning("The obj parameter in KnowledgeBase.__init__() has been deprecated.")
        object.__setattr__(self, "_project", project)
        object.__setattr__(self, "_plugins", {})
        object.__setattr__(self, "name", name or f"kb_{next(kb_ctr)}")

    @property
    def callgraph(self):
        return self.functions.callgraph

    @property
    def unresolved_indirect_jumps(self):
        return self.indirect_jumps.unresolved

    @property
    def resolved_indirect_jumps(self):
        return self.indirect_jumps.resolved

    def __setstate__(self, state):
        self.__dict__.update(state)

        # iterate over a copy: set_kb() may lazily create plugins (e.g., rtdb) and mutate self._plugins
        for plugin in list(self._plugins.values()):
            plugin.set_kb(self)

    def __dir__(self):
        x = list(super().__dir__())
        x.extend(default_plugins.keys())
        return x

    #
    # Plugin accessor
    #

    def __contains__(self, plugin_name):
        return plugin_name in self._plugins

    def __getattr__(self, v):
        try:
            return self.get_plugin(v)
        except KeyError as err:
            raise AttributeError(v) from err

    def __setattr__(self, k, v):
        self.register_plugin(k, v)

    #
    # Plugins
    #

    def has_plugin(self, name):
        return name in self._plugins

    def get_plugin(self, name):
        if name not in self._plugins:
            p = default_plugins[name](self)
            self.register_plugin(name, p)
            return p
        return self._plugins[name]

    def register_plugin(self, name, plugin):
        self._plugins[name] = plugin
        return plugin

    def release_plugin(self, name):
        if name in self._plugins:
            del self._plugins[name]

    def get_knowledge[K: KnowledgeBasePlugin](self, requested_plugin_cls: type[K]) -> K | None:
        """
        Type inference safe method to request a knowledge base plugin
        Explicitly passing the type of the requested plugin achieves two things:
        1. Every location using this plugin can be easily found with an IDE by searching explicit references to the type
        2. Basic type inference can deduce the result type and properly type check usages of it

        If there isn't already an instance of this class None will be returned to make it clear to the caller that there
        is no existing knowledge of this type yet. The code that initially creates this knowledge should use the
        `register_plugin` method to register the initial knowledge state
        :param requested_plugin_cls:
        :return: Instance of the requested plugin class or null if it is not a known plugin
        """
        # Get first plugin of this type already registered, or default to None
        return next((plugin for plugin in self._plugins.values() if isinstance(plugin, requested_plugin_cls)), None)

    def request_knowledge[K: KnowledgeBasePlugin](self, requested_plugin_cls: type[K]) -> K:
        existing = self.get_knowledge(requested_plugin_cls)
        if existing is not None:
            return existing
        p = requested_plugin_cls(self)
        self.register_plugin(requested_plugin_cls.__name__, p)
        return p


class KnowledgeBaseSnapshot:
    """
    A restore point for a :class:`KnowledgeBase`, so that the same project and CFG can be analyzed repeatedly (for
    example, decompiling one function under several option sets) from an identical starting state.

    A snapshot records:

    - the plugin table, as a shallow copy of the name-to-plugin mapping;
    - by-value copies of the plugins named in ``included_plugins`` (default :attr:`COPIED_PLUGINS`) that exist at
      snapshot time;
    - for each function resident in memory, its per-flavor prototypes, prototype sources, set of resolved flavors,
      and calling convention.

    Without a rollback, a later :class:`~angr.analyses.decompiler.Decompiler` run sees the callee prototypes that
    Clinic installed on :class:`~angr.knowledge_plugins.functions.Function` objects during an earlier run, inherits
    that run's variable numbering through ``dec_variables``, and, when its cache parameters match, reuses the earlier
    ``decompilations`` entry instead of running the pipeline.

    Functions are captured by object identity, and only the resident ones, because iterating a spilling function dict
    would evict the :class:`~angr.knowledge_plugins.functions.Function` objects that callers hold. As a result,
    prototype changes on functions that were spilled at snapshot time and loaded later are not rolled back.
    """

    # analyses mutate these in place, so they are restored by value
    COPIED_PLUGINS = ("types", "custom_strings", "callsite_prototypes", "comments", "variables")

    def __init__(self, kb: KnowledgeBase, included_plugins: Iterable[str] | None = None):
        """
        :param kb:               The knowledge base to snapshot.
        :param included_plugins: Names of the plugins to restore by value; the others are kept by reference. Defaults
                                 to :attr:`COPIED_PLUGINS`.
        """
        self._kb = kb
        self._plugins = dict(kb._plugins)
        names = self.COPIED_PLUGINS if included_plugins is None else tuple(included_plugins)
        self._copies = {name: self._plugins[name].copy() for name in names if name in self._plugins}
        self._prototypes = {
            func: (
                dict(func._prototypes),
                dict(func._prototype_sources),
                set(func._prototypes_resolved),
                func.calling_convention,
            )
            for func in self._resident_functions(kb)
        }

    @staticmethod
    def _resident_functions(kb: KnowledgeBase) -> list[Function]:
        fmap = kb.functions._function_map
        if isinstance(fmap, SpillingFunctionDict):
            return list(fmap.data.values())
        return list(fmap.values())

    def restore(self) -> None:
        """
        Roll the knowledge base back to this snapshot. Plugins created after the snapshot are removed. Each included
        plugin is replaced by a fresh copy of the snapshot's copy, so the snapshot itself is never modified. All other
        plugins are reinstated by reference, which means changes made to them in place are kept.
        Resident functions get their prototype state back. This method may be called any number of times.
        """
        plugins = self._kb._plugins
        plugins.clear()
        plugins.update(self._plugins)
        for name, plugin in self._copies.items():
            plugins[name] = plugin.copy()
            plugins[name].set_kb(self._kb)
        for func, (prototypes, sources, resolved, cc) in self._prototypes.items():
            func._prototypes = dict(prototypes)
            func._prototype_sources = dict(sources)
            func._prototypes_resolved = set(resolved)
            func.calling_convention = cc
