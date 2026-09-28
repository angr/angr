"""Developer debug traps that do not abort batch runs.

The VM-deobfuscation analyses mark "this should not happen" states with
``import ipdb; ipdb.set_trace()``. That is useful interactively, but in a batch run there is
no tty: ipdb raises ``BdbQuit`` and the whole analysis dies at a point the code only meant to
inspect.

``debug_trap`` keeps the diagnostic and drops the abort. Set ``PUSHAN_DEBUG_TRAPS=1`` to get
the interactive debugger back.
"""

from __future__ import annotations

import logging
import os
import sys

_l = logging.getLogger(__name__)

_ENV = "PUSHAN_DEBUG_TRAPS"


def traps_enabled() -> bool:
    return os.environ.get(_ENV, "").lower() in {"1", "true", "yes", "y"}


def debug_trap(message: str, **context) -> None:
    """Log that an unexpected state was reached and continue.

    With ``PUSHAN_DEBUG_TRAPS=1`` set, break into ipdb at the caller's frame instead.
    """
    if traps_enabled():
        import ipdb  # pylint:disable=import-outside-toplevel

        ipdb.set_trace(sys._getframe().f_back)
        return
    if context:
        detail = ", ".join(f"{k}={v!r}" for k, v in context.items())
        _l.warning("debug trap: %s (%s)", message, detail)
    else:
        _l.warning("debug trap: %s", message)
