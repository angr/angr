import os
import time
from pathlib import Path
import logging


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

        base = Path(__file__).parent
        self.sig_dirs = sig_dirs or [base / "flirt_sigs", base / "flirt_sigs_no_inline"]
        self._cache = {}
        self.matched_count = 0
        self.rust_symbols = {}

        if self.project.rustc_version is None:
            l.info("Auto-detecting rustc version (sig_dirs=%s)", self.sig_dirs)
            start_time = time.time()
            self._identify_rustc_version()
            elapsed = time.time() - start_time
            l.info(
                "Detection completed in %.2f seconds: rustc %s (matched %d functions)",
                elapsed,
                self.project.rustc_version,
                self.matched_count,
            )

        self._analyze()

    @staticmethod
    def _parse_version(filename):
        """Parse version and opt level from filename like '1.87.0-O3.sig'"""
        name = filename.replace(".sig", "")
        parts = name.rsplit("-O", 1)
        version = parts[0]
        opt_level = parts[1] if len(parts) > 1 else ""
        v_parts = version.split(".")
        return tuple(int(x) for x in v_parts), opt_level

    def _match_signature(self, sig_path):
        """Match a single signature file and return the number of matched std/core/alloc functions."""
        try:
            fa = self.project.analyses.Flirt(sig_path, dry_run=True)
            matched = fa.matched_suggestions["Temporary"][1]  # {addr: name}
            count = 0
            for addr, name in matched.items():
                name = demangle(name)
                if not (name.startswith("core::") or name.startswith("std::") or name.startswith("alloc::")):
                    continue
                count += 1
            return count
        except Exception:
            return 0

    def _cached_count(self, sig_file):
        """Return the best match count across all sig dirs for comparison between versions."""
        if sig_file not in self._cache:
            best_count = 0
            for sig_dir in self.sig_dirs:
                sig_path = os.path.join(sig_dir, sig_file)
                if os.path.exists(sig_path):
                    count = self._match_signature(sig_path)
                    if count > best_count:
                        best_count = count
            self._cache[sig_file] = best_count
            l.info("[%d] Testing %s: %d matches", len(self._cache), sig_file, best_count)
        return self._cache[sig_file]

    def _identify_rustc_version(self):
        # Ensure CFG exists
        if self.project.kb.cfgs.get_most_accurate() is None:
            self.project.analyses.CFGFast(normalize=True)

        # Get all sig files (deduplicated) and group by opt level
        sig_files_set = set()
        for sig_dir in self.sig_dirs:
            if os.path.isdir(sig_dir):
                sig_files_set.update(f for f in os.listdir(sig_dir) if f.endswith(".sig"))
        sig_files = list(sig_files_set)
        sigs_by_opt = {opt: [] for opt in self.OPT_LEVELS}
        for f in sig_files:
            _, opt = self._parse_version(f)
            if opt in sigs_by_opt:
                sigs_by_opt[opt].append(f)

        # Sort each opt level by version (newest first)
        for opt in self.OPT_LEVELS:
            sigs_by_opt[opt].sort(key=lambda x: self._parse_version(x)[0], reverse=True)

        # Phase 1: Find approximate version range using O3 as probe
        probe_opt = "3"
        l.info("Phase 1: Find approximate version range (probe opt=O%s)", probe_opt)
        probe_sigs = sigs_by_opt[probe_opt]
        n_samples = min(10, len(probe_sigs))
        step = max(1, len(probe_sigs) // n_samples)
        sample_indices = list(range(0, len(probe_sigs), step))[:n_samples]

        version_scores = [(idx, self._cached_count(probe_sigs[idx])) for idx in sample_indices]
        best_probe_idx = max(version_scores, key=lambda x: x[1])[0]
        l.info("Best probe version: %s at index %d", probe_sigs[best_probe_idx], best_probe_idx)

        # Phase 2: Fine search around best probe region
        left = max(0, best_probe_idx - step)
        right = min(len(probe_sigs) - 1, best_probe_idx + step)
        l.info("Phase 2: Fine search in range [%d, %d] around best probe", left, right)

        best_idx = best_probe_idx
        best_count = self._cached_count(probe_sigs[best_probe_idx])
        for i in range(left, right + 1):
            c = self._cached_count(probe_sigs[i])
            if c > best_count:
                best_count = c
                best_idx = i

        best_version, _ = self._parse_version(probe_sigs[best_idx])
        self.project.rustc_version = ".".join(str(x) for x in best_version)
        self.matched_count = self._cache[probe_sigs[best_idx]]
        l.info(
            "Best match: %s, matched %d functions (tested %d/%d sig files)",
            probe_sigs[best_idx].replace(".sig", ""),
            self.matched_count,
            len(self._cache),
            len(sig_files),
        )

        # Phase 3: Compare sig dirs and select the best one
        best_sig_dir = self.sig_dirs[0]
        best_dir_count = 0
        best_sig_file = probe_sigs[best_idx]
        for sig_dir in self.sig_dirs:
            sig_path = os.path.join(sig_dir, best_sig_file)
            if os.path.exists(sig_path):
                count = self._match_signature(sig_path)
                l.info("Phase 3: %s count=%d for %s", sig_dir, count, best_sig_file)
                if count > best_dir_count:
                    best_dir_count = count
                    best_sig_dir = sig_dir
        self.best_sig_dir = best_sig_dir
        l.info("Selected sig dir: %s", self.best_sig_dir)

    def _analyze(self):
        version = self.project.rustc_version
        sig_dir = getattr(self, "best_sig_dir", self.sig_dirs[0])
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

        for func in self.project.kb.functions.values():
            if func.from_signature == "flirt":
                self.rust_symbols[func.addr] = demangle(func.name)
        l.info("Recovered %d rust symbols (after Flirt)", len(self.rust_symbols))

        self.project.analyses.FlirtSigPropagation(cfg=self.project.kb.cfgs.get_most_accurate())

        for func in self.project.kb.functions.values():
            if func.from_signature == "flirt":
                self.rust_symbols[func.addr] = demangle(func.name)
        l.info("Recovered %d rust symbols (after FlirtSigPropagation)", len(self.rust_symbols))

        self.project.analyses.CleanupFunctionIdentification()

        for func in self.project.kb.functions.values():
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
