
import logging

from ...engines.light import SimEngineLight
from ...errors import SimEngineError

l = logging.getLogger(name=__name__)


class SimEnginePropagatorBase(SimEngineLight):  # pylint:disable=abstract-method
    def __init__(self, stack_pointer_tracker=None, project=None):
        super().__init__()

        # Used in the VEX engine
        self._project = project
        self.base_state = None
        self._load_callback = None

        # Used in the AIL engine
        self._stack_pointer_tracker = stack_pointer_tracker

    def process(self, state, *args, **kwargs):
        self.project = kwargs.pop('project', None)
        self.base_state = kwargs.pop('base_state', None)
        self._load_callback = kwargs.pop('load_callback', None)
        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as ex:
            if kwargs.pop('fail_fast', False) is True:
                raise ex
            l.error(ex, exc_info=True)

        return self.state
