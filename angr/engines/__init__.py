from __future__ import annotations

from .engine import SimEngine
from .failure import SimEngineFailure
from .hook import HooksMixin
from .procedure import ProcedureEngine, ProcedureMixin
from .soot import SootMixin
from .successors import SimSuccessors, SuccessorsEngine
from .syscall import SimEngineSyscall
from .unicorn import SimEngineUnicorn
from .vex import HeavyResilienceMixin, HeavyVEXMixin, SimInspectMixin, SuperFastpathMixin, TrackActionsMixin


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
    """
    The default execution engine for angr. This engine includes mixins for most
    common functionality in angr, including VEX IR, unicorn, syscall handling,
    and simprocedure handling.

    For some performance-sensitive applications, you may want to create a custom
    engine with only the necessary mixins.
    """


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
    "SuccessorsEngine",
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
