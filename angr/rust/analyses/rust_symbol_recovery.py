import os
import struct
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

    def __init__(self, inline=False, sig_dir=None):
        super().__init__()

        self.sig_dir = sig_dir or Path(__file__).parent / ("flirt_sigs_no_inline" if not inline else "flirt_sigs")
        self._cache = {}
        self.matched_count = 0
        self.rust_symbols = {}

        if self.project.rustc_version is None:
            l.info("Auto-detecting rustc version (sig_dir=%s)", self.sig_dir)
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

    @staticmethod
    def _get_sig_nfuncs(sig_path):
        """Read nfuncs from a FLIRT signature file header without parsing the full tree."""
        with open(sig_path, "rb") as f:
            header_fmt = "<6sBBIHHHHH12sBH"
            sz = struct.calcsize(header_fmt)
            header = f.read(sz)
            unpacked = struct.unpack(header_fmt, header)
            version = unpacked[1]
            if version >= 6:
                return max(struct.unpack("<I", f.read(4))[0], 1)
        return 1

    def _match_signature(self, sig_path):
        """Match a single signature file and return (match_count, match_score).

        match_score = match_count / nfuncs, normalized so that signature files with
        more patterns don't have an unfair advantage.
        """
        try:
            fa = self.project.analyses.Flirt(sig_path, dry_run=True)
            matched = fa.matched_suggestions["Temporary"][1]  # {addr: name}
            nfuncs = self._get_sig_nfuncs(sig_path)
            count = 0
            for addr, name in matched.items():
                name = demangle(name)
                if not (name.startswith("core::") or name.startswith("std::") or name.startswith("alloc::")):
                    continue
                count += 1
            score = count / nfuncs
            return count, score
        except Exception:
            return 0, 0.0

    def _cached_score(self, sig_file):
        """Return the match score (match_count / nfuncs) for comparison between versions."""
        if sig_file not in self._cache:
            sig_path = os.path.join(self.sig_dir, sig_file)
            count, score = self._match_signature(sig_path)
            self._cache[sig_file] = (count, score)
            l.info("[%d] Testing %s: %d matches (score=%.4f)", len(self._cache), sig_file, count, score)
        return self._cache[sig_file][1]

    def _identify_rustc_version(self):
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

        # Phase 1: Find approximate version range using O3 as probe
        probe_opt = "3"
        l.info("Phase 1: Find approximate version range (probe opt=O%s)", probe_opt)
        probe_sigs = sigs_by_opt[probe_opt]
        n_samples = min(10, len(probe_sigs))
        step = max(1, len(probe_sigs) // n_samples)
        sample_indices = list(range(0, len(probe_sigs), step))[:n_samples]

        version_scores = [(idx, self._cached_score(probe_sigs[idx])) for idx in sample_indices]
        best_probe_idx = max(version_scores, key=lambda x: x[1])[0]
        l.info("Best probe version: %s at index %d", probe_sigs[best_probe_idx], best_probe_idx)

        # Phase 2: Fine search around best probe region
        left = max(0, best_probe_idx - step)
        right = min(len(probe_sigs) - 1, best_probe_idx + step)
        l.info("Phase 2: Fine search in range [%d, %d] around best probe", left, right)

        best_idx = best_probe_idx
        best_score = self._cached_score(probe_sigs[best_probe_idx])
        for i in range(left, right + 1):
            s = self._cached_score(probe_sigs[i])
            if s > best_score:
                best_score = s
                best_idx = i

        best_version, _ = self._parse_version(probe_sigs[best_idx])
        self.project.rustc_version = ".".join(str(x) for x in best_version)
        self.matched_count = self._cache[probe_sigs[best_idx]][0]
        l.info(
            "Best match: %s, matched %d functions (tested %d/%d sig files)",
            probe_sigs[best_idx].replace(".sig", ""),
            self.matched_count,
            len(self._cache),
            len(sig_files),
        )

    def _analyze(self):
        version = self.project.rustc_version
        applied = 0
        for opt in self.OPT_LEVELS:
            sig_path = Path(self.sig_dir) / f"{version}-O{opt}.sig"
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
