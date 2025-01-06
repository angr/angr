from __future__ import annotations

from .successors import SimSuccessors
from .engine import SimEngine, SuccessorsMixin

from .vex import HeavyVEXMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from .procedure import ProcedureMixin, ProcedureEngine
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
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
    HeavyVEXMixin,
):
    pass


__all__ = [
    "HeavyResilienceMixin",
    "HeavyVEXMixin",
    "HooksMixin",
    "ProcedureEngine",
    "ProcedureMixin",
    "SimEngine",
    "SimEngineFailure",
    "SimEngineSyscall",
    "SimEngineUnicorn",
    "SimInspectMixin",
    "SimSuccessors",
    "SootMixin",
    "SuccessorsMixin",
    "SuperFastpathMixin",
    "TrackActionsMixin",
    "UberEngine",
]


try:
    from .pcode import HeavyPcodeMixin

    class UberEnginePcode(
        SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin
    ):  # pylint:disable=abstract-method
        pass

    __all__.append("UberEnginePcode")

except ImportError:
    pass
