from __future__ import annotations

from . import optimization_passes, structuring
from .ail_simplifier import AILSimplifier
from .block_simplifier import BlockSimplifier
from .callsite_maker import CallSiteMaker
from .clinic import Clinic
from .decompilation_options import options, options_by_category
from .decompiler import Decompiler
from .dephication import GraphDephication, SeqNodeDephication
from .presets import DECOMPILATION_PRESETS
from .region_identifier import RegionIdentifier
from .region_simplifiers import RegionSimplifier
from .ssailification import Ssailification
from .structured_codegen import CStructuredCodeGenerator, ImportSourceCode

StructuredCodeGenerator = CStructuredCodeGenerator


__all__ = (
    "DECOMPILATION_PRESETS",
    "AILSimplifier",
    "BlockSimplifier",
    "CStructuredCodeGenerator",
    "CallSiteMaker",
    "Clinic",
    "Decompiler",
    "GraphDephication",
    "ImportSourceCode",
    "RegionIdentifier",
    "RegionSimplifier",
    "SeqNodeDephication",
    "Ssailification",
    "StructuredCodeGenerator",
    "optimization_passes",
    "options",
    "options_by_category",
    "structuring",
)
