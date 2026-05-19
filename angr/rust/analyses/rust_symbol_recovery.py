from __future__ import annotations

import logging
from pathlib import Path

from angr.analyses import Analysis, AnalysesHub
from angr.rust.utils.demangler import demangle

l = logging.getLogger(name=__name__)


class RustSymbolRecovery(Analysis):
    """
    This analysis recovers Rust symbols by analyzing the binary's symbol table and debug information.
    It identifies Rust-specific symbols, such as those related to traits, generics, and async functions,
    and annotates them for further analysis.
    """

    OPT_LEVELS = ["0", "1", "2", "3"]

    def __init__(self, sig_dirs=None):
        super().__init__()

        self.rust_symbols = {}

        version_id = self.project.analyses.RustcVersionIdentification(sig_dirs=sig_dirs)
        self.matched_count = version_id.matched_count
        self.best_sig_dir = version_id.best_sig_dir

        self._analyze()

    def _analyze(self):
        version = self.project.rustc_version
        sig_dir = self.best_sig_dir
        if version is None or sig_dir is None:
            l.info("No rustc version or signature directory found, skipping rust symbol recovery")
            return
        applied = 0
        for opt in self.OPT_LEVELS:
            sig_path = Path(sig_dir) / f"{version}-O{opt}.sig"
            if sig_path.exists():
                l.info("Applying signatures from %s", sig_path)
                self.project.analyses.Flirt(str(sig_path))
                applied += 1

        if applied == 0:
            l.info("No signature files found for version %s", version)
            return

        l.info("Applied %d signature files for version %s", applied, version)

        for func in self.project.kb.functions.values(meta_only=True):
            if func.from_signature == "flirt":
                self.rust_symbols[func.addr] = demangle(func.name)
        l.info("Recovered %d rust symbols (after Flirt)", len(self.rust_symbols))

        self.project.analyses.FlirtSigPropagation(cfg=self.project.kb.cfgs.get_most_accurate())

        for func in self.project.kb.functions.values(meta_only=True):
            if func.from_signature == "flirt":
                self.rust_symbols[func.addr] = demangle(func.name)
        l.info("Recovered %d rust symbols (after FlirtSigPropagation)", len(self.rust_symbols))

        self.project.analyses.CleanupFunctionIdentification()

        for func in self.project.kb.functions.values(meta_only=True):
            if func.from_signature == "flirt":
                self.rust_symbols[func.addr] = demangle(func.name)
        l.info("Recovered %d rust symbols (after CleanupFunctionIdentification)", len(self.rust_symbols))

        total_functions = len(self.project.kb.functions)
        l.info(
            "Final count: %d rust symbols out of %d total functions (%.2f%%)",
            len(self.rust_symbols),
            total_functions,
            100 * len(self.rust_symbols) / total_functions,
        )


AnalysesHub.register_default("RustSymbolRecovery", RustSymbolRecovery)
