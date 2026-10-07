from __future__ import annotations

from .x86_dirty import X86DirtyRewriter


class AMD64DirtyRewriter(X86DirtyRewriter):
    """
    Rewrites AMD64 DirtyStatement and DirtyExpression. The helpers mirror the X86 ones under a different prefix.
    """

    __slots__ = ()

    HELPER_PREFIX = "amd64g_dirtyhelper_"
