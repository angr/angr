from .concrete import SimEngineConcrete
from .engine import SimEngine, SuccessorsMixin, TLSMixin
from .failure import SimEngineFailure
from .hook import HooksMixin
from .procedure import ProcedureEngine, ProcedureMixin
from .soot import SootMixin
from .successors import SimSuccessors
from .syscall import SimEngineSyscall
from .unicorn import SimEngineUnicorn
from .vex import HeavyResilienceMixin, HeavyVEXMixin, SimInspectMixin, SuperFastpathMixin, TrackActionsMixin


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
    HeavyVEXMixin,
    TLSMixin,
):
    pass


try:
    from .pcode import HeavyPcodeMixin

    class UberEnginePcode(
        SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin
    ):  # pylint:disable=abstract-method
        pass

except ImportError:
    pass
