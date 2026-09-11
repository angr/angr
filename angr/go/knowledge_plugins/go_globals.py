from __future__ import annotations

import logging

from angr.go.signature import GoVariable
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

l = logging.getLogger(__name__)


class GoGlobals(KnowledgeBasePlugin):
    """
    Package-level variables recovered without data symbols: the runtime's own globals located by shape
    (:mod:`angr.go.analyses.runtime_globals`) and the variables typed from their initializers
    (:mod:`angr.go.analyses.package_variables`). Computed once per project on first use;
    ``kb.go_signatures.variable_at`` consults it after the symbol-backed sources.
    """

    def __init__(self, kb):
        super().__init__(kb)
        self._by_addr: dict[int, GoVariable] = {}
        self._by_name: dict[str, GoVariable] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        project = self._kb._project
        if project is None or not getattr(project, "is_go_binary", False):
            return
        # lazy imports: the analyses pull in the AIL converter
        from angr.go.analyses.package_variables import infer_package_variables  # pylint:disable=import-outside-toplevel
        from angr.go.analyses.runtime_globals import find_runtime_globals  # pylint:disable=import-outside-toplevel

        try:
            for var in find_runtime_globals(project).values():
                self.note(var)
        except Exception:  # pylint:disable=broad-exception-caught
            l.warning("Locating Go runtime globals failed", exc_info=True)
        try:
            for var in infer_package_variables(project):
                self.note(var)
        except Exception:  # pylint:disable=broad-exception-caught
            l.warning("Typing Go package variables failed", exc_info=True)

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
