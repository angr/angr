# pylint:disable=protected-access
from __future__ import annotations

import logging

from angr.go.signature import GoVariable
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

l = logging.getLogger(__name__)


class GoGlobals(KnowledgeBasePlugin):
    """
    Package-level variables recovered without data symbols: the runtime's own globals located by shape
    (:mod:`angr.go.analyses.runtime_globals`) and the variables typed from their initializers
    (:mod:`angr.go.analyses.package_variables`). Computed once per project by
    :class:`angr.go.analyses.go_globals_recovery.GoGlobalsRecovery`, lazily on first use unless it was run ahead of
    time; ``kb.go_signatures.variable_at`` consults it after the symbol-backed sources.
    """

    def __init__(self, kb):
        super().__init__(kb)
        self._by_addr: dict[int, GoVariable] = {}
        self._by_name: dict[str, GoVariable] = {}
        self._loaded = False

    def load(self) -> None:
        """Run :class:`GoGlobalsRecovery` once; later calls are no-ops."""
        if self._loaded:
            return
        project = self._kb._project
        if project is None:
            self._loaded = True
            return
        self._loaded = True  # set first: the analysis itself consults this plugin
        project.analyses.GoGlobalsRecovery(kb=self._kb)

    def mark_loaded(self) -> None:
        self._loaded = True

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def variables(self) -> dict[int, GoVariable]:
        self.load()
        return self._by_addr

    def note(self, var: GoVariable, replace: bool = False) -> None:
        """Record a variable; an address already known keeps its first record unless ``replace``."""
        if not replace and var.addr in self._by_addr:
            return
        self._by_addr[var.addr] = var
        self._by_name[var.name] = var

    def variable_at(self, addr: int) -> GoVariable | None:
        self.load()
        return self._by_addr.get(addr)

    def addr_of(self, name: str) -> int | None:
        self.load()
        var = self._by_name.get(name)
        return var.addr if var is not None else None

    def copy(self):
        o = GoGlobals(self._kb)
        o._by_addr = dict(self._by_addr)
        o._by_name = dict(self._by_name)
        o._loaded = self._loaded
        return o


KnowledgeBasePlugin.register_default("go_globals", GoGlobals)
