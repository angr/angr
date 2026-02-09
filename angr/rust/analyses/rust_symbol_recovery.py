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

    # OPT_LEVELS = ["0", "1", "2", "3", "s", "z"]
    OPT_LEVELS = ["0", "1", "2", "3"]

    def __init__(self, sig_dir=None):
        super().__init__()

        self.sig_dir = sig_dir or Path(__file__).parent / "flirt_sigs"
        self._cache = {}
        self.matched_count = 0
        self.rust_symbols = {}

        if self.project.rustc_version is None or self.project.rustc_optimization_level is None:
            l.debug("Auto-detecting rustc version and optimization level (sig_dir=%s)", self.sig_dir)
            start_time = time.time()
            self._identify_rustc_version_and_optimization_level()
            elapsed = time.time() - start_time
            l.debug(
                "Detection completed in %.2f seconds: rustc %s -O%s (matched %d functions)",
                elapsed,
                self.project.rustc_version,
                self.project.rustc_optimization_level,
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
        """Match a single signature file and return count."""
        try:
            fa = self.project.analyses.Flirt(sig_path, dry_run=True)
            matched_functions = fa.matched_suggestions["Temporary"][1].values()
            matched_functions = [demangle(name) for name in matched_functions]
            matched_functions = [
                name
                for name in matched_functions
                if name.startswith("core::") or name.startswith("std::") or name.startswith("alloc::")
            ]
            return len(matched_functions)
        except Exception:
            return 0

    def _cached_count(self, sig_file):
        if sig_file not in self._cache:
            sig_path = os.path.join(self.sig_dir, sig_file)
            count = self._match_signature(sig_path)
            self._cache[sig_file] = count
            l.debug("[%d] Testing %s: %d matches", len(self._cache), sig_file, count)
        return self._cache[sig_file]

    def _identify_rustc_version_and_optimization_level(self):
        # Ensure CFG exists
        if self.project.kb.cfgs.get_most_accurate() is None:
            self.project.analyses.CFGFast(normalize=True)

        # Get all sig files and group by opt level
        sig_files = [f for f in os.listdir(self.sig_dir) if f.endswith(".sig")]
        sigs_by_opt = {opt: [] for opt in self.OPT_LEVELS}
        for f in sig_files:
            _, opt = self._parse_version(f)
            if opt in sigs_by_opt:
                sigs_by_opt[opt].append(f)

        # Sort each opt level by version (newest first)
        for opt in self.OPT_LEVELS:
            sigs_by_opt[opt].sort(key=lambda x: self._parse_version(x)[0], reverse=True)

        # Phase 1: Find approximate version range using O2 as probe
        probe_opt = "3"
        l.debug(f"Phase 1: Find approximate version range (probe opt=O{probe_opt})")
        probe_sigs = sigs_by_opt[probe_opt]
        n_samples = min(10, len(probe_sigs))
        step = max(1, len(probe_sigs) // n_samples)
        sample_indices = list(range(0, len(probe_sigs), step))[:n_samples]

        version_scores = [(idx, self._cached_count(probe_sigs[idx])) for idx in sample_indices]
        best_probe_idx = max(version_scores, key=lambda x: x[1])[0]
        best_probe_version = self._parse_version(probe_sigs[best_probe_idx])[0]
        l.debug("Best probe version: %s at index %d", probe_sigs[best_probe_idx], best_probe_idx)

        # Phase 2: Determine opt level around best version
        l.debug("Phase 2: Determine optimization level around best version")
        opt_scores = {}
        for opt in self.OPT_LEVELS:
            sigs = sigs_by_opt[opt]
            if not sigs:
                continue
            # Find the closest version to best_probe_version
            closest_idx = 0
            closest_diff = float("inf")
            for i, sig in enumerate(sigs):
                v, _ = self._parse_version(sig)
                diff = abs(
                    v[0] * 1000000
                    + v[1] * 1000
                    + v[2]
                    - best_probe_version[0] * 1000000
                    - best_probe_version[1] * 1000
                    - best_probe_version[2]
                )
                if diff < closest_diff:
                    closest_diff = diff
                    closest_idx = i

            test_range = range(max(0, closest_idx - 2), min(len(sigs), closest_idx + 3))
            opt_scores[opt] = max(self._cached_count(sigs[i]) for i in test_range)
            l.debug("O%s: max score = %d", opt, opt_scores[opt])

        best_opt = max(opt_scores, key=opt_scores.get)
        l.debug("Best opt level: O%s", best_opt)

        # Phase 3: Ternary search for best version
        l.debug("Phase 3: Ternary search in O%s", best_opt)
        filtered_sigs = sigs_by_opt[best_opt]
        left, right = 0, len(filtered_sigs) - 1

        while right - left > 3:
            mid1 = left + (right - left) // 3
            mid2 = right - (right - left) // 3
            if self._cached_count(filtered_sigs[mid1]) < self._cached_count(filtered_sigs[mid2]):
                left = mid1
            else:
                right = mid2

        # Fine search in remaining range
        l.debug("Fine search in range [%d, %d]", left, right)
        best_idx = left
        best_count = self._cached_count(filtered_sigs[left])
        for i in range(left, right + 1):
            c = self._cached_count(filtered_sigs[i])
            if c > best_count:
                best_count = c
                best_idx = i

        best_version, _ = self._parse_version(filtered_sigs[best_idx])
        self.project.rustc_version = ".".join(str(x) for x in best_version)
        self.project.rustc_optimization_level = best_opt
        self.matched_count = self._cache[filtered_sigs[best_idx]]
        l.debug(
            "Best match: %s, matched %d functions (tested %d/%d sig files)",
            filtered_sigs[best_idx].replace(".sig", ""),
            self.matched_count,
            len(self._cache),
            len(sig_files),
        )

    def _analyze(self):
        sig_path = Path(self.sig_dir) / f"{self.project.rustc_version}-O{self.project.rustc_optimization_level}.sig"
        if sig_path.exists():
            l.debug("Applying signatures from %s", sig_path)
            self.project.analyses.Flirt(str(sig_path))

            for func in self.project.kb.functions.values():
                if func.from_signature == "flirt":
                    self.rust_symbols[func.addr] = demangle(func.name)
            l.debug("Recovered %d rust symbols (after Flirt)", len(self.rust_symbols))

            self.project.analyses.FlirtSigPropagation(cfg=self.project.kb.cfgs.get_most_accurate())

            for func in self.project.kb.functions.values():
                if func.from_signature == "flirt":
                    self.rust_symbols[func.addr] = demangle(func.name)
            l.debug("Recovered %d rust symbols (after FlirtSigPropagation)", len(self.rust_symbols))

            self.project.analyses.CleanupFunctionIdentification()

            for func in self.project.kb.functions.values():
                if func.from_signature == "flirt":
                    self.rust_symbols[func.addr] = demangle(func.name)
            l.debug("Recovered %d rust symbols (after CleanupFunctionIdentification)", len(self.rust_symbols))

            total_functions = len(self.project.kb.functions)
            l.debug(
                "Final count: %d rust symbols out of %d total functions (%.2f%%)",
                len(self.rust_symbols),
                total_functions,
                100 * len(self.rust_symbols) / total_functions,
            )
        else:
            l.debug("Signature file not found: %s", sig_path)


AnalysesHub.register_default("RustSymbolRecovery", RustSymbolRecovery)
