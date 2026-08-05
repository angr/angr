"""Fuzzy repeated-code discovery for decompiled functions.

Inlined duplicated code -- obfuscator decryption stubs, expanded macros, copies
of an inlined helper -- is almost never byte-identical: constants differ per
site and the optimizer reorders and reassociates around them. Exact matching
therefore finds nothing useful, which is why this package canonicalizes an AIL
graph into a token stream (:mod:`.tokenizer`) and runs a sparse local
self-alignment over it (:mod:`.align`) to recover the near-duplicate families.

Families alone cannot be merged: members that align at 90% still differ
somewhere. :mod:`.exact` therefore extracts the sub-ranges on which a family
agrees exactly modulo constants, and :mod:`.dedup` outlines those into a single
shared function with the differing constants lifted into parameters.
"""

from __future__ import annotations

__all__ = [
    "AILCanonicalizer",
    "AlignParams",
    "Alignment",
    "DedupResult",
    "ExactCore",
    "FuzzyPattern",
    "FuzzyPatternFinder",
    "Interval",
    "MergeGroup",
    "PatternCluster",
    "PatternDeduplicator",
    "PatternOccurrence",
    "Region",
    "TokenLoc",
    "TokenStream",
    "discover",
    "find_exact_cores",
    "linearize",
    "materialize",
    "select_disjoint",
    "snap",
    "tokenize",
]

from .align import Alignment, AlignParams, Interval, PatternCluster, discover, select_disjoint
from .dedup import DedupResult, MergeGroup, PatternDeduplicator
from .exact import ExactCore, find_exact_cores
from .finder import FuzzyPattern, FuzzyPatternFinder, PatternOccurrence
from .region import Region, materialize, snap
from .tokenizer import AILCanonicalizer, TokenLoc, TokenStream, linearize, tokenize
