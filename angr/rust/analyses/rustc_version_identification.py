from __future__ import annotations

import os
import time
from pathlib import Path
import logging

from angr.analyses import Analysis, AnalysesHub
from angr.rust.utils.demangler import demangle
from angr.rust.utils.rust_sigs import get_default_sig_dir

l = logging.getLogger(name=__name__)


class RustcVersionIdentification(Analysis):
    """
    Identify the rustc version used to compile a Rust binary by matching FLIRT signatures
    across known rustc versions and selecting the version with the highest match count.
    """

    OPT_LEVELS = ["0", "1", "2", "3"]

    def __init__(self, sig_dirs=None):
        super().__init__()

        self.sig_dirs = []
        self._cache = {}
        self.matched_count = 0
        self.best_sig_dir = None

        base_dir = get_default_sig_dir()
        if base_dir is None or not os.path.isdir(base_dir):
            l.warning("No valid signature directory found, skipping rustc version identification")
            return

        base = Path(base_dir)
        self.sig_dirs = sig_dirs or [base / "inline", base / "no-inline"]
        self.best_sig_dir = self.sig_dirs[0]

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
        else:
            self._select_best_sig_dir_for_version(self.project.rustc_version)

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
            fa = self.project.analyses.Flirt(sig_path, dry_run=True, match_named_functions=True)
            matched = fa.matched_suggestions["Temporary"][1]  # {addr: name}
            count = 0
            for _addr, name in matched.items():
                name = demangle(name)
                if not name.startswith(("core::", "std::", "alloc::")):
                    continue
                count += 1
            return count
        except Exception:  # pylint:disable=broad-exception-caught
            return 0

    def _cached_count(self, sig_file):
        """Return the best match count across all sig dirs for comparison between versions."""
        if sig_file not in self._cache:
            best_count = 0
            for sig_dir in self.sig_dirs:
                sig_path = os.path.join(sig_dir, sig_file)
                if os.path.exists(sig_path):
                    count = self._match_signature(sig_path)
                    best_count = max(best_count, count)
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

        self._select_best_sig_dir(probe_sigs[best_idx])

    def _select_best_sig_dir_for_version(self, version):
        best_sig_file = f"{version}-O3.sig"
        self._select_best_sig_dir(best_sig_file)

    def _select_best_sig_dir(self, best_sig_file):
        # Compare sig dirs and select the best one
        best_sig_dir = self.sig_dirs[0]
        best_dir_count = 0
        for sig_dir in self.sig_dirs:
            sig_path = os.path.join(sig_dir, best_sig_file)
            if os.path.exists(sig_path):
                count = self._match_signature(sig_path)
                l.info("Signature directory check: %s count=%d for %s", sig_dir, count, best_sig_file)
                if count > best_dir_count:
                    best_dir_count = count
                    best_sig_dir = sig_dir
        self.matched_count = best_dir_count
        self.best_sig_dir = best_sig_dir
        l.info("Selected sig dir: %s", self.best_sig_dir)


AnalysesHub.register_default("RustcVersionIdentification", RustcVersionIdentification)
