from __future__ import annotations

from angr.analyses.analysis import AnalysesHub
from angr.analyses.typehoon.typehoon import Typehoon


class GoTypehoon(Typehoon):
    """Go-aware type inference engine. Identical to Typehoon until Go SimTypes land."""


AnalysesHub.register_default("GoTypehoon", GoTypehoon)
