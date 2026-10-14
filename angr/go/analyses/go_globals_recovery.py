from __future__ import annotations

import logging

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.go.analyses.package_variables import infer_package_variables
from angr.go.analyses.runtime_globals import find_runtime_globals

l = logging.getLogger(__name__)


class GoGlobalsRecovery(Analysis):
    """
    Recover Go package-level variables without data symbols and record them in ``kb.go_globals``: the runtime's own
    globals located by shape (:mod:`angr.go.analyses.runtime_globals`), then the variables typed from their
    initializers (:mod:`angr.go.analyses.package_variables`). Requires a CFG; a no-op on non-Go binaries.

    Supports ``progress_callback`` and ``low_priority``, so a GUI can run it in the background.
    """

    def __init__(self, low_priority: bool = False):
        """
        :param low_priority: Run in the background: periodically release the GIL.
        """
        super().__init__()
        self._low_priority = low_priority
        self.go_globals = self.kb.go_globals
        self._analyze()

    def _analyze(self) -> None:
        self._update_progress(0.0, text="Recovering Go globals")
        if self.project.is_go_binary:
            # a whole-binary scan run once: the signatures it looks up are no dependency of any decompilation
            with self.kb.go_signatures.untracked():
                self._find_runtime_globals()
                self._infer_package_variables()
        self.go_globals.mark_loaded()
        self._finish_progress()

    def _find_runtime_globals(self) -> None:
        self._update_progress(0.0, text="Locating Go runtime globals")
        try:
            for var in find_runtime_globals(self.project).values():
                self.go_globals.note(var)
        except Exception:  # pylint:disable=broad-exception-caught
            l.warning("Locating Go runtime globals failed", exc_info=True)

    def _infer_package_variables(self) -> None:
        self._update_progress(10.0, text="Typing Go package variables")

        def on_initializer(i: int, n: int) -> None:
            self._update_progress(10.0 + 90.0 * i / n, text=f"Typing Go package variables ({i}/{n})")
            if self._low_priority:
                self._release_gil(i + 1, 1)

        try:
            for var in infer_package_variables(self.project, on_initializer=on_initializer):
                self.go_globals.note(var)
        except Exception:  # pylint:disable=broad-exception-caught
            l.warning("Typing Go package variables failed", exc_info=True)


AnalysesHub.register_default("GoGlobalsRecovery", GoGlobalsRecovery)
