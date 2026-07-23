from __future__ import annotations

import logging

from archinfo.arch_arm import is_arm_arch

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.errors import AngrRuntimeError, AngrValueError
from angr.knowledge_plugins.cfg import MemoryDataSort

from .flirt import MAX_UNIQUE_STRING_LEN

_l = logging.getLogger(name=__name__)

MIN_STRING_LEN = 6


class SuggestSignatureAnalysis(Analysis):
    """
    SuggestSignatureAnalysis queries a sigserv signature server with string and integer constants recovered from the
    binary (as found in the most accurate CFG model) to suggest FLIRT signatures that likely match statically linked
    libraries in the binary. Suggestions whose number of matched constants meets ``min_matches`` are accepted, and,
    when ``apply`` is set, each accepted signature is matched against the binary via FlirtAnalysis.

    Results are stored in ``suggestions`` (all arch-compatible suggestions returned by sigserv), ``accepted`` (the
    accepted subset, best-scored first), and ``applied`` (sig_path to number of matched functions, when ``apply`` is
    set).
    """

    def __init__(
        self,
        signatures_dir: str | None = None,
        db_url: str | None = None,
        sig_server=None,
        apply: bool = True,
        min_matches: int = 2,
        max_signatures: int | None = None,
        platform: str | None = None,
        max_mismatched_bytes: int = 0,
    ):
        try:
            import sigserv  # pylint:disable=import-outside-toplevel
        except ImportError as ex:
            raise AngrRuntimeError(
                "sigserv is not installed; install it with pip install sigserv to use SuggestSignature"
            ) from ex

        if sum(1 for src in (signatures_dir, db_url, sig_server) if src is not None) != 1:
            raise AngrValueError("Exactly one of signatures_dir, db_url, or sig_server must be provided")

        if sig_server is None:
            sig_server = (
                sigserv.SigServer(signatures_dir=signatures_dir)
                if signatures_dir is not None
                else sigserv.SigServer(db_url=db_url)
            )
        self._sig_server = sig_server

        cfg_model = self.kb.cfgs.get_most_accurate()
        if cfg_model is None or not cfg_model.memory_data:
            raise AngrRuntimeError("A CFG with memory data is required; run CFGFast before SuggestSignature")

        self.query_strings: list[str] = self._collect_strings(cfg_model)
        self.query_integers: list[int] = self._collect_integers(cfg_model)

        suggestions = self._sig_server.query(
            strings=self.query_strings, integers=self.query_integers, arch=None, platform=platform
        )
        self.suggestions: list[dict] = [s for s in suggestions if self._arch_matches(s["meta"].get("arch"))]

        accepted = [
            s for s in self.suggestions if len(s["matched_strings"]) + len(s["matched_integers"]) >= min_matches
        ]
        accepted.sort(key=lambda s: s["score"], reverse=True)
        if max_signatures is not None:
            accepted = accepted[:max_signatures]
        self.accepted: list[dict] = accepted

        self.applied: dict[str, int] = {}
        if apply:
            for s in self.accepted:
                sig_path = s["sig_path"]
                _l.info("Applying suggested FLIRT signature %s (library %s).", sig_path, s["library_name"])
                flirt = self.project.analyses.Flirt(sig_path, max_mismatched_bytes=max_mismatched_bytes)
                self.applied[sig_path] = sum(len(d) for _, d in flirt.matched_suggestions.values())

    def _collect_strings(self, cfg_model) -> list[str]:
        strings: set[str] = set()
        for md in cfg_model.memory_data.values():
            if md.sort != MemoryDataSort.String:
                continue
            content = md.content
            if content is None:
                if not md.size:
                    continue
                content = self.project.loader.memory.load(md.addr, md.size)
            try:
                s = content.decode("ascii", errors="ignore")
            except (UnicodeDecodeError, AttributeError):
                continue
            s = s.rstrip("\x00")
            if len(s) < MIN_STRING_LEN:
                continue
            strings.add(s[:MAX_UNIQUE_STRING_LEN])
        return sorted(strings)

    def _collect_integers(self, cfg_model) -> list[int]:
        endness = "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
        min_addr = self.project.loader.min_addr
        max_addr = self.project.loader.max_addr
        integers: set[int] = set()
        for md in cfg_model.memory_data.values():
            if md.sort != MemoryDataSort.Integer or md.size not in (4, 8):
                continue
            try:
                raw = self.project.loader.memory.load(md.addr, md.size)
            except KeyError:
                continue
            if len(raw) != md.size:
                continue
            v = int.from_bytes(raw, endness)
            if v < 0x10000 or v > 0x7FFF_FFFF_FFFF_FFFF:
                # too small to be a meaningful constant, or does not fit in a signed 64-bit integer
                continue
            if min_addr <= v <= max_addr and self.project.loader.find_object_containing(v) is not None:
                # pointer-looking value; skip
                continue
            integers.add(v)
        return sorted(integers)

    def _arch_matches(self, sig_arch: str | None) -> bool:
        if not sig_arch:
            return False
        sig_arch = sig_arch.lower()
        if sig_arch == self.project.arch.name.lower():
            return True
        # ARMHF may use ARMEL libraries
        return sig_arch == "armel" and is_arm_arch(self.project.arch)


AnalysesHub.register_default("SuggestSignature", SuggestSignatureAnalysis)
