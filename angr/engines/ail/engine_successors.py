from __future__ import annotations
from angr.ailment.block import Block
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors, SuccessorsEngine


class AILMixin(SuccessorsEngine):
    def process_successors(self, successors: SimSuccessors, block: Block | None = None, **kwargs):
        if not isinstance(successors.addr, tuple):
            super().process_successors(successors, block=block, **kwargs)

        successors.sort = "AIL"
        successors.description = f"AIL block {successors.addr[0]:#x}{'.' if successors.addr[1] is not None else ''}{successors.addr[1] if successors.addr[1] is not None else ''}"

        subengine = SimEngineAILSimState(self.project, successors)
        subengine.process(self.state, block=block)

        successors.processed = True
