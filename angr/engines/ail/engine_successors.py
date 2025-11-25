from __future__ import annotations

from angr.ailment.block import Block
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors, SuccessorsEngine


class AILMixin(SuccessorsEngine):
    """
    The SuccessorsEngine mixin for providing AIL symbolic execution support
    """

    def process_successors(self, successors: SimSuccessors, block: Block | None = None, **kwargs):
        if not isinstance(successors.addr, tuple):
            super().process_successors(successors, block=block, **kwargs)
            return

        successors.sort = "AIL"
        successors.description = "AIL block"

        subengine = SimEngineAILSimState(self.project, successors)
        subengine.process(self.state, block=block)  # type: ignore

        successors.processed = True
