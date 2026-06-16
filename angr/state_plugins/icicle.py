from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.sim_state import SimState

from .plugin import SimStatePlugin

if TYPE_CHECKING:
    from angr.rustylib.icicle import Icicle


@dataclass
class IcicleStateTranslationData:
    """
    Represents the saved information needed to convert an Icicle state back
    to an angr state.
    """

    base_state: SimState[int, int]
    registers: set[str]
    mapped_pages: set[int]
    writable_pages: set[int]
    explicit_page_metadata: dict[int, int | None]
    initial_cpu_icount: int
    icicle_arch: str


@dataclass
class IcicleVMRef:
    """Holder shared by reference across plugin copies.

    Lets multiple SimStateIcicle plugins point at the same VM and observe each
    other's advancements via `generation`: each successful engine run bumps
    `generation`, invalidating any plugin still holding the prior value.
    """

    vm: Icicle
    generation: int = 0


class SimStateIcicle(SimStatePlugin):
    """Engine-internal plugin for IcicleEngine continuation detection.

    Attached to states produced by ``IcicleEngine.process()``. Owns the VM and
    the metadata the engine needs to decide whether the next call is a
    lightweight continuation or requires a full snapshot restore.
    """

    def __init__(
        self,
        vm_ref: IcicleVMRef | None = None,
        generation: int | None = None,
        base_translation_data: IcicleStateTranslationData | None = None,
        translation_data: IcicleStateTranslationData | None = None,
        dirty_pages: set[int] | None = None,
    ):
        super().__init__()
        self.vm_ref = vm_ref
        self.generation = generation
        self.base_translation_data = base_translation_data
        self.translation_data = translation_data
        self.dirty_pages = dirty_pages if dirty_pages is not None else set()

    @property
    def is_live(self) -> bool:
        """True when the VM is still positioned where this state last left it."""
        return self.vm_ref is not None and self.generation == self.vm_ref.generation

    def set_state(self, state):
        pass  # no weak ref needed

    @SimStatePlugin.memo
    def copy(self, _memo):
        return SimStateIcicle(
            vm_ref=self.vm_ref,
            generation=self.generation,
            base_translation_data=self.base_translation_data,
            translation_data=self.translation_data,
            dirty_pages=set(self.dirty_pages),
        )

    def merge(self, others, merge_conditions, common_ancestor=None):
        return False

    def widen(self, others):
        return False


SimState.register_default("icicle", SimStateIcicle)
