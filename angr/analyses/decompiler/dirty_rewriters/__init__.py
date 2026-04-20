from __future__ import annotations
from .amd64_dirty import AMD64DirtyRewriter
from .x86_dirty import X86DirtyRewriter

DIRTY_REWRITERS = {
    "AMD64": AMD64DirtyRewriter,
    "X86": X86DirtyRewriter,
}
