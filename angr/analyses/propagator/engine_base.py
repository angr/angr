from __future__ import annotations
from typing import TYPE_CHECKING, Generic
import logging


from angr.engines.light.engine import BlockType, DataType_co, StateType

from angr.engines.light import SimEngineLight
from angr.errors import SimEngineError
from angr.project import Project
from angr.misc.testing import is_testing

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsModel

l = logging.getLogger(name=__name__)


class SimEnginePropagatorBaseMixin(
    Generic[StateType, DataType_co, BlockType], SimEngineLight[StateType, DataType_co, BlockType, StateType]
):  # pylint:disable=abstract-method
    """
    The base class for the propagator VEX engine.
    """

    def __init__(
        self,
        project: Project,
        stack_pointer_tracker=None,
        propagate_tmps=True,
        reaching_definitions: ReachingDefinitionsModel | None = None,
        bp_as_gpr: bool = False,
    ):
        super().__init__(project)

        # Used in the VEX engine
        self.arch = project.arch
        self.base_state = None
        self._load_callback = None
        self._propagate_tmps: bool = propagate_tmps
        self._reaching_definitions = reaching_definitions
        self.bp_as_gpr = bp_as_gpr

        # Used in the AIL engine
        self._stack_pointer_tracker = stack_pointer_tracker

        self._multi_occurrence_registers = None

    def process(
        self, state: StateType, *, block: BlockType | None = None, base_state=None, load_callback=None, **kwargs
    ) -> StateType:
        self.base_state = base_state
        self._load_callback = load_callback
        try:
            result_state = super().process(state, block=block, **kwargs)
        except SimEngineError as ex:
            if kwargs.pop("fail_fast", is_testing) is True:
                raise ex
            l.error(ex, exc_info=True)
            result_state = state

        return result_state
