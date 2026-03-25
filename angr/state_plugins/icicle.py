from __future__ import annotations

from typing import TYPE_CHECKING

from .plugin import SimStatePlugin

if TYPE_CHECKING:
    from angr.engines.icicle import IcicleStateTranslationData


class SimStateIcicle(SimStatePlugin):
    """Engine-internal plugin for IcicleEngine continuation detection.

    Attached to states produced by ``IcicleEngine.process_concrete()``.
    Carries the metadata the engine needs to decide whether the next call
    is a lightweight continuation or requires a full snapshot restore.

    This plugin is NOT registered as a default -- it is only attached by
    the engine.
    """

    def __init__(
        self,
        engine_id: int,
        run_id: int,
        translation_data: IcicleStateTranslationData,
        page_ids: dict[int, int | None],
        dirty_pages: set[int],
    ):
        super().__init__()
        self.engine_id = engine_id
        self.run_id = run_id
        self.translation_data = translation_data
        self.page_ids = page_ids
        self.dirty_pages = dirty_pages

    def set_state(self, state):
        pass  # no weak ref needed

    @SimStatePlugin.memo
    def copy(self, _memo):
        return SimStateIcicle(
            engine_id=self.engine_id,
            run_id=self.run_id,
            translation_data=self.translation_data,
            page_ids=dict(self.page_ids),
            dirty_pages=set(self.dirty_pages),
        )

    def merge(self, others, merge_conditions, common_ancestor=None):
        return False

    def widen(self, others):
        return False
