from __future__ import annotations

import zlib

_TAG_CACHE: dict[type, int] = {}


def type_tag(cls: type) -> int:
    """
    Return a stable, process-independent integer tag for ``cls``.
    """
    tag = _TAG_CACHE.get(cls)
    if tag is None:
        tag = _TAG_CACHE[cls] = zlib.crc32(cls.__qualname__.encode())
    return tag
