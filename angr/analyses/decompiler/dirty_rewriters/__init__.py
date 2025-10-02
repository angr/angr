from __future__ import annotations
from .amd64_dirty import AMD64DirtyRewriter


DIRTY_REWRITERS = {
    "AMD64": AMD64DirtyRewriter,
}
