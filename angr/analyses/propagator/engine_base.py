from typing import Optional, TYPE_CHECKING
import logging

from ...engines.light import SimEngineLight
from ...errors import SimEngineError

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsModel

l = logging.getLogger(name=__name__)


class SimEnginePropagatorBase(SimEngineLight):  # pylint:disable=abstract-method
    def __init__(
        self,
        stack_pointer_tracker=None,
        project=None,
        propagate_tmps=True,
        arch=None,
        reaching_definitions: Optional["ReachingDefinitionsModel"] = None,
        immediate_stmt_removal: bool = False,
        bp_as_gpr: bool = False,
    ):
        super().__init__()

        # Used in the VEX engine
        self._project = project
        self.arch = arch
        self.base_state = None
        self._load_callback = None
        self._propagate_tmps: bool = propagate_tmps
        self._reaching_definitions = reaching_definitions
        self._immediate_stmt_removal = immediate_stmt_removal
        self.bp_as_gpr = bp_as_gpr
        self.stmts_to_remove = set()

        # Used in the AIL engine
        self._stack_pointer_tracker = stack_pointer_tracker

        self._multi_occurrence_registers = None

    def process(self, state, *args, **kwargs):
        self.project = kwargs.pop("project", None)
        self.base_state = kwargs.pop("base_state", None)
        self._load_callback = kwargs.pop("load_callback", None)
        try:
            self._process(state, None, block=kwargs.pop("block", None))
        except SimEngineError as ex:
            if kwargs.pop("fail_fast", False) is True:
                raise ex
            l.error(ex, exc_info=True)

        return self.state
