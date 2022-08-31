import time
import pickle
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class ProfilingEventBase:
    timestamp: int = field(default_factory=time.time_ns)


@dataclass
class ProjectCreatedEvent(ProfilingEventBase):
    binary: str = ""
    options: Dict[str,Any] = field(default_factory=dict)


@dataclass
class StateCreatedEvent(ProfilingEventBase):
    state_id: str = ""
    addr: Optional[int] = -1
    parent_state_id: Optional[str] = None


@dataclass
class StateStashedEvent(ProfilingEventBase):
    state_id: str = ""
    stash_name: str = None


@dataclass
class StateErroredEvent(ProfilingEventBase):
    state_id: str = ""
    addr: Optional[int] = None


class Profiling:
    """
    This class saves limited profiling information about several angr events, including:

    - project creation
    - state creation
    - state termination
    """

    __slots__ = ('events', )

    def __init__(self):
        self.events = [ ]

    def project_created(self, binary: str, options: Dict[str,Any]) -> None:
        self.events.append(
            ProjectCreatedEvent(binary=binary, options=options)
        )

    def state_created(self, state_id: str, addr: Optional[int], parent_state_id: Optional[str]) -> None:
        self.events.append(
            StateCreatedEvent(state_id=state_id, addr=addr, parent_state_id=parent_state_id)
        )

    def state_stashed(self, state_id: str, stash_name: str) -> None:
        self.events.append(
            StateStashedEvent(state_id=state_id, stash_name=stash_name)
        )

    def state_errored(self, state_id: str, addr: Optional[int]) -> None:
        self.events.append(
            StateErroredEvent(state_id=state_id, addr=addr)
        )

    def dump(self, file_object) -> None:
        pickle.dump(self.events, file_object)

    def load(self, file_object) -> None:
        self.events = pickle.load(file_object)
