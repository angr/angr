from __future__ import annotations

from .dream import DreamStructurer
from .phoenix import PhoenixStructurer
from .recursive_structurer import RecursiveStructurer
from .sailr import SAILRStructurer

STRUCTURER_CLASSES = {
    SAILRStructurer.NAME: SAILRStructurer,
    PhoenixStructurer.NAME: PhoenixStructurer,
    DreamStructurer.NAME: DreamStructurer,
}

DEFAULT_STRUCTURER = SAILRStructurer


def structurer_class_from_name(name: str) -> type | None:
    return STRUCTURER_CLASSES.get(name.lower())


__all__ = (
    "DEFAULT_STRUCTURER",
    "STRUCTURER_CLASSES",
    "DreamStructurer",
    "PhoenixStructurer",
    "RecursiveStructurer",
    "SAILRStructurer",
    "structurer_class_from_name",
)
