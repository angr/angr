from __future__ import annotations

from .region_identifier import RegionIdentifier
from .structured_codegen import CStructuredCodeGenerator, ImportSourceCode
from .clinic import Clinic
from .region_simplifiers import RegionSimplifier
from .decompiler import Decompiler
from .decompilation_options import options, options_by_category
from .block_simplifier import BlockSimplifier
from .callsite_maker import CallSiteMaker
from .ail_simplifier import AILSimplifier
from .ssailification import Ssailification
from .dephication import GraphDephication, SeqNodeDephication
from .presets import DECOMPILATION_PRESETS
from . import structuring
from . import optimization_passes


StructuredCodeGenerator = CStructuredCodeGenerator


__all__ = (
    "RegionIdentifier",
    "CStructuredCodeGenerator",
    "ImportSourceCode",
    "Clinic",
    "RegionSimplifier",
    "Decompiler",
    "options",
    "options_by_category",
    "BlockSimplifier",
    "CallSiteMaker",
    "AILSimplifier",
    "Ssailification",
    "GraphDephication",
    "SeqNodeDephication",
    "DECOMPILATION_PRESETS",
    "structuring",
    "optimization_passes",
    "StructuredCodeGenerator",
)
