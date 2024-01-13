from typing import Optional, Type

from .dream import DreamStructurer
from .phoenix import PhoenixStructurer
from .combing import CombingStructurer
from .recursive_structurer import RecursiveStructurer


STRUCTURER_CLASSES = {
    "dream": DreamStructurer,
    "phoenix": PhoenixStructurer,
    "combing": CombingStructurer,
}


def structurer_class_from_name(name: str) -> Optional[Type]:
    return STRUCTURER_CLASSES.get(name.lower(), None)
