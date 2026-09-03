from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.go.analyses.type_descriptors import GoTypeDescriptors, read_go_type_descriptors
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.go.signature import GoSignatureSet
    from angr.sim_type import SimType

l = logging.getLogger(__name__)


class GoTypes(KnowledgeBasePlugin):
    """
    The runtime type descriptors of this binary (:mod:`angr.go.analyses.type_descriptors`), parsed once on first use:
    descriptor address <-> canonical Go type string, itabs, and the named-type records that back
    ``kb.go_signatures``.
    """

    def __init__(self, kb):
        super().__init__(kb)
        self._descriptors: GoTypeDescriptors | None = None

    @property
    def descriptors(self) -> GoTypeDescriptors:
        if self._descriptors is None:
            project = self._kb._project
            if project is None:
                self._descriptors = GoTypeDescriptors()
            else:
                try:
                    self._descriptors = read_go_type_descriptors(project)
                except Exception as e:  # pylint:disable=broad-exception-caught
                    l.warning("Reading Go type descriptors failed: %s", e, exc_info=True)
                    self._descriptors = GoTypeDescriptors()
        return self._descriptors

    @property
    def loaded(self) -> bool:
        return self._descriptors is not None

    @property
    def go_version(self) -> str | None:
        return self.descriptors.go_version

    @property
    def types(self) -> GoSignatureSet:
        return self.descriptors.types

    def name_at(self, addr: int) -> str | None:
        """The canonical Go type string of the descriptor at ``addr``."""
        return self.descriptors.resolve(addr)

    def addr_of(self, name: str) -> int | None:
        """The descriptor address of the type spelled ``name``."""
        return self.descriptors.name_to_addr.get(name)

    def itab_at(self, addr: int) -> tuple[str, str] | None:
        """``(interface type, concrete type)`` of the itab at ``addr``."""
        return self.descriptors.resolve_itab(addr)

    def type_at(self, addr: int) -> SimType | None:
        """The SimType of the descriptor at ``addr``, built by ``kb.go_signatures``."""
        name = self.name_at(addr)
        if name is None:
            return None
        sigs = self._kb.go_signatures
        sigs.load_sources()
        try:
            return sigs.type(name)
        except Exception as e:  # pylint:disable=broad-exception-caught
            l.debug("Cannot build a SimType for %r: %s", name, e)
            return None

    def copy(self):
        o = GoTypes(self._kb)
        o._descriptors = self._descriptors
        return o


KnowledgeBasePlugin.register_default("go_types", GoTypes)
