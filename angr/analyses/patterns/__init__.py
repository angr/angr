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

from .search import (
    TemplateColumn,
    TemplateMatch,
    find_template_occurrences,
    search,
    template_leaves,
    tokenize_for_templates,
    verify,
)
from .template import TEMPLATE_TOKENIZER, Fit, match_shape, parse_shape, shape_of

__all__ = [
    "TEMPLATE_TOKENIZER",
    "AILCanonicalizer",
    "AlignParams",
    "Alignment",
    "Checkpoint",
    "DedupResult",
    "ExactCore",
    "Fit",
    "FuzzyPattern",
    "FuzzyPatternFinder",
    "Interval",
    "MergeGroup",
    "PatternCluster",
    "PatternDeduplicator",
    "PatternOccurrence",
    "Region",
    "TemplateColumn",
    "TemplateMatch",
    "TokenLoc",
    "TokenStream",
    "discover",
    "find_exact_cores",
    "find_template_occurrences",
    "linearize",
    "match_shape",
    "materialize",
    "parse_shape",
    "search",
    "select_disjoint",
    "shape_of",
    "snap",
    "template_leaves",
    "tokenize",
    "tokenize_for_templates",
    "verify",
]

from .align import Alignment, AlignParams, Interval, PatternCluster, discover, select_disjoint
from .dedup import DedupResult, MergeGroup, PatternDeduplicator
from .exact import ExactCore, find_exact_cores
from .finder import FuzzyPattern, FuzzyPatternFinder, PatternOccurrence
from .priority import Checkpoint
from .region import Region, materialize, snap
from .tokenizer import AILCanonicalizer, TokenLoc, TokenStream, linearize, tokenize
