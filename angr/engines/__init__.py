from .successors import SimSuccessors
from .engine import SimEngine, SuccessorsMixin

from .vex import HeavyVEXMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from .procedure import ProcedureMixin, ProcedureEngine
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
from .concrete import SimEngineConcrete
from .hook import HooksMixin
from .soot import SootMixin


# The default execution engine
# You may remove unused mixins from this default engine to speed up execution
class UberEngine(
        SimEngineFailure,
        SimEngineSyscall,
        HooksMixin,
        SimEngineUnicorn,
        SuperFastpathMixin,
        TrackActionsMixin,
        SimInspectMixin,
        HeavyResilienceMixin,
        SootMixin,
        HeavyVEXMixin
):
    pass


try:
    from .pcode import HeavyPcodeMixin

    class UberEnginePcode(SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin):  # pylint:disable=abstract-method
        pass
except ImportError:
    pass
