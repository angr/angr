from __future__ import annotations

from typing import TYPE_CHECKING

from angr.sim_state import SimState

from .plugin import SimStatePlugin

if TYPE_CHECKING:
    from angr.engines.icicle import IcicleStateTranslationData


class SimStateIcicle(SimStatePlugin):
    """Engine-internal plugin for IcicleEngine continuation detection.

    Attached to states produced by ``IcicleEngine.process()``.
    Carries the metadata the engine needs to decide whether the next call
    is a lightweight continuation or requires a full snapshot restore.
    """

    def __init__(
        self,
        engine_id: int | None = None,
        run_id: int | None = None,
        translation_data: IcicleStateTranslationData | None = None,
        dirty_pages: set[int] | None = None,
    ):
        super().__init__()
        self.engine_id = engine_id
        self.run_id = run_id
        self.translation_data = translation_data
        self.dirty_pages = dirty_pages if dirty_pages is not None else set()

    def set_state(self, state):
        pass  # no weak ref needed

    @SimStatePlugin.memo
    def copy(self, _memo):
        return SimStateIcicle(
            engine_id=self.engine_id,
            run_id=self.run_id,
            translation_data=self.translation_data,
            dirty_pages=set(self.dirty_pages),
        )

    def merge(self, others, merge_conditions, common_ancestor=None):
        return False

    def widen(self, others):
        return False


SimState.register_default("icicle", SimStateIcicle)
