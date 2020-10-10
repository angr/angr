from .successors import SimSuccessors
from .engine import SimEngine, SuccessorsMixin

from .vex import HeavyVEXMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from .procedure import ProcedureMixin, ProcedureEngine
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
from .remote_syscall import SimEngineRemoteSyscall
from .concrete import SimEngineConcrete
from .hook import HooksMixin
from .soot import SootMixin

class UberEngine(
    SimEngineFailure,
    SimEngineRemoteSyscall,
    SimEngineSyscall,
    HooksMixin,
    SimEngineUnicorn,
    SuperFastpathMixin,
    TrackActionsMixin,
    SimInspectMixin,
    HeavyResilienceMixin,
    SootMixin,
    HeavyVEXMixin):
    pass

try:
    from .pcode import HeavyPcodeMixin
    class UberEnginePcode(SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin): # pylint:disable=abstract-method
        pass
except ImportError:
    pass
