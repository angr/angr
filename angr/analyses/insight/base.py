from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.analysis import Analysis

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel


class InsightBase(Analysis):
    DESCRIPTION = None

    def __init__(self, cfg=None):
        super().__init__()

        self.cfg: CFGModel = cfg
