from __future__ import annotations

import zlib

_TAG_CACHE: dict[type, int] = {}


def type_tag(cls: type) -> int:
    """
    Return a stable, process-independent integer tag for ``cls``.

    The built-in ``hash(cls)`` is derived from the class object's identity (its memory address), which differs
    from one process to the next. Embedding it in ``__hash__`` therefore makes the hashes of type-system
    objects -- and the iteration order of every set, dict, or graph that contains them -- vary across runs,
    which is a source of non-deterministic type inference. Hashing on a CRC of the qualified name instead is
    stable across processes and independent of ``PYTHONHASHSEED``.
    """
    tag = _TAG_CACHE.get(cls)
    if tag is None:
        tag = _TAG_CACHE[cls] = zlib.crc32(cls.__qualname__.encode())
    return tag
