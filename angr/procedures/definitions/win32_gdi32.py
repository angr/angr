# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from ...sim_type import (SimTypeFunction,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeDouble,
    SimTypeFloat,
    SimTypePointer,
    SimTypeChar,
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimUnion,
    SimTypeBool,
    SimTypeRef,
)
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("gdi32.dll")
prototypes = \
    {
        #
        'BRUSHOBJ_pvAllocRbrush': SimTypeFunction([SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pbo", "cj"]),
        #
        'BRUSHOBJ_pvGetRbrush': SimTypeFunction([SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pbo"]),
        #
        'BRUSHOBJ_ulGetBrushColor': SimTypeFunction([SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbo"]),
        #
        'BRUSHOBJ_hGetColorTransform': SimTypeFunction([SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbo"]),
        #
        'CLIPOBJ_cEnumStart': SimTypeFunction([SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pco", "bAll", "iType", "iDirection", "cLimit"]),
        #
        'CLIPOBJ_bEnum': SimTypeFunction([SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pco", "cj", "pul"]),
        #
        'CLIPOBJ_ppoGetPath': SimTypeFunction([SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), arg_names=["pco"]),
        #
        'FONTOBJ_cGetAllGlyphHandles': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfo", "phg"]),
        #
        'FONTOBJ_vGetInfo': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FONTINFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pfo", "cjSize", "pfi"]),
        #
        'FONTOBJ_cGetGlyphs': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfo", "iMode", "cGlyph", "phg", "ppvGlyph"]),
        #
        'FONTOBJ_pxoGetXform': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeRef("XFORMOBJ", SimStruct), offset=0), arg_names=["pfo"]),
        #
        'FONTOBJ_pifi': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IFIMETRICS", SimStruct), offset=0), arg_names=["pfo"]),
        #
        'FONTOBJ_pfdg': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FD_GLYPHSET", SimStruct), offset=0), arg_names=["pfo"]),
        #
        'FONTOBJ_pvTrueTypeFontFile': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pfo", "pcjFile"]),
        #
        'FONTOBJ_pQueryGlyphAttrs': SimTypeFunction([SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("FD_GLYPHATTR", SimStruct), offset=0), arg_names=["pfo", "iMode"]),
        #
        'PATHOBJ_vEnumStart': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ppo"]),
        #
        'PATHOBJ_bEnum': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("PATHDATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppo", "ppd"]),
        #
        'PATHOBJ_vEnumStartClipLines': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINEATTRS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ppo", "pco", "pso", "pla"]),
        #
        'PATHOBJ_bEnumClipLines': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLIPLINE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppo", "cb", "pcl"]),
        #
        'PATHOBJ_vGetBounds': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTFX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ppo", "prectfx"]),
        #
        'STROBJ_vEnumStart': SimTypeFunction([SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pstro"]),
        #
        'STROBJ_bEnum': SimTypeFunction([SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("GLYPHPOS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstro", "pc", "ppgpos"]),
        #
        'STROBJ_bEnumPositionsOnly': SimTypeFunction([SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("GLYPHPOS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstro", "pc", "ppgpos"]),
        #
        'STROBJ_dwGetCodePage': SimTypeFunction([SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pstro"]),
        #
        'STROBJ_bGetAdvanceWidths': SimTypeFunction([SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTQF", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "iFirst", "c", "pptqD"]),
        #
        'XFORMOBJ_iGetXform': SimTypeFunction([SimTypePointer(SimTypeRef("XFORMOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XFORML", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pxo", "pxform"]),
        #
        'XFORMOBJ_bApplyXform': SimTypeFunction([SimTypePointer(SimTypeRef("XFORMOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pxo", "iMode", "cPoints", "pvIn", "pvOut"]),
        #
        'XLATEOBJ_iXlate': SimTypeFunction([SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pxlo", "iColor"]),
        #
        'XLATEOBJ_piVector': SimTypeFunction([SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), arg_names=["pxlo"]),
        #
        'XLATEOBJ_cGetPalette': SimTypeFunction([SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pxlo", "iPal", "cPal", "pPal"]),
        #
        'XLATEOBJ_hGetColorTransform': SimTypeFunction([SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pxlo"]),
        #
        'EngCreateBitmap': SimTypeFunction([SimTypeRef("SIZE", SimStruct), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["sizl", "lWidth", "iFormat", "fl", "pvBits"]),
        #
        'EngCreateDeviceSurface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("SIZE", SimStruct), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dhsurf", "sizl", "iFormatCompat"]),
        #
        'EngCreateDeviceBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("SIZE", SimStruct), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dhsurf", "sizl", "iFormatCompat"]),
        #
        'EngDeleteSurface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hsurf"]),
        #
        'EngLockSurface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), arg_names=["hsurf"]),
        #
        'EngUnlockSurface': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pso"]),
        #
        'EngEraseSurface': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "prcl", "iColor"]),
        #
        'EngAssociateSurface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hsurf", "hdev", "flHooks"]),
        #
        'EngMarkBandingSurface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hsurf"]),
        #
        'EngCheckAbort': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pso"]),
        #
        'EngDeletePath': SimTypeFunction([SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ppo"]),
        #
        'EngCreatePalette': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["iMode", "cColors", "pulColors", "flRed", "flGreen", "flBlue"]),
        #
        'EngDeletePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hpal"]),
        #
        'EngCreateClip': SimTypeFunction([], SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0)),
        #
        'EngDeleteClip': SimTypeFunction([SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pco"]),
        #
        'EngBitBlt': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoTrg", "psoSrc", "psoMask", "pco", "pxlo", "prclTrg", "pptlSrc", "pptlMask", "pbo", "pptlBrush", "rop4"]),
        #
        'EngLineTo': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "pco", "pbo", "x1", "y1", "x2", "y2", "prclBounds", "mix"]),
        #
        'EngStretchBlt': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("COLORADJUSTMENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDest", "psoSrc", "psoMask", "pco", "pxlo", "pca", "pptlHTOrg", "prclDest", "prclSrc", "pptlMask", "iMode"]),
        #
        'EngStretchBltROP': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("COLORADJUSTMENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDest", "psoSrc", "psoMask", "pco", "pxlo", "pca", "pptlHTOrg", "prclDest", "prclSrc", "pptlMask", "iMode", "pbo", "rop4"]),
        #
        'EngAlphaBlend': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("BLENDOBJ", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDest", "psoSrc", "pco", "pxlo", "prclDest", "prclSrc", "pBlendObj"]),
        #
        'EngGradientFill': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRIVERTEX", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDest", "pco", "pxlo", "pVertex", "nVertex", "pMesh", "nMesh", "prclExtents", "pptlDitherOrg", "ulMode"]),
        #
        'EngTransparentBlt': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDst", "psoSrc", "pco", "pxlo", "prclDst", "prclSrc", "TransColor", "bCalledFromBitBlt"]),
        #
        'EngTextOut': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("STROBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("FONTOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "pstro", "pfo", "pco", "prclExtra", "prclOpaque", "pboFore", "pboOpaque", "pptlOrg", "mix"]),
        #
        'EngStrokePath': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XFORMOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINEATTRS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "ppo", "pco", "pxo", "pbo", "pptlBrushOrg", "plineattrs", "mix"]),
        #
        'EngFillPath': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "ppo", "pco", "pbo", "pptlBrushOrg", "mix", "flOptions"]),
        #
        'EngStrokeAndFillPath': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("PATHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XFORMOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINEATTRS", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "ppo", "pco", "pxo", "pboStroke", "plineattrs", "pboFill", "pptlBrushOrg", "mixFill", "flOptions"]),
        #
        'EngPaint': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("BRUSHOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pso", "pco", "pbo", "pptlBrushOrg", "mix"]),
        #
        'EngCopyBits': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psoDest", "psoSrc", "pco", "pxlo", "prclDest", "pptlSrc"]),
        #
        'EngPlgBlt': SimTypeFunction([SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("SURFOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIPOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("XLATEOBJ", SimStruct), offset=0), SimTypePointer(SimTypeRef("COLORADJUSTMENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTFIX", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psoTrg", "psoSrc", "psoMsk", "pco", "pxlo", "pca", "pptlBrushOrg", "pptfx", "prcl", "pptl", "iMode"]),
        #
        'HT_Get8BPPFormatPalette': SimTypeFunction([SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPaletteEntry", "RedGamma", "GreenGamma", "BlueGamma"]),
        #
        'HT_Get8BPPMaskPalette': SimTypeFunction([SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPaletteEntry", "Use8BPPMaskPal", "CMYMask", "RedGamma", "GreenGamma", "BlueGamma"]),
        #
        'EngGetPrinterDataFileName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["hdev"]),
        #
        'EngGetDriverName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["hdev"]),
        #
        'EngLoadModule': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwsz"]),
        #
        'EngFindResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["h", "iName", "iType", "pulSize"]),
        #
        'EngFreeModule': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["h"]),
        #
        'EngCreateSemaphore': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'EngAcquireSemaphore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hsem"]),
        #
        'EngReleaseSemaphore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hsem"]),
        #
        'EngDeleteSemaphore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hsem"]),
        #
        'EngMultiByteToUnicodeN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["UnicodeString", "MaxBytesInUnicodeString", "BytesInUnicodeString", "MultiByteString", "BytesInMultiByteString"]),
        #
        'EngUnicodeToMultiByteN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MultiByteString", "MaxBytesInMultiByteString", "BytesInMultiByteString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'EngQueryLocalTime': SimTypeFunction([SimTypePointer(SimTypeRef("ENG_TIME_FIELDS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0"]),
        #
        'EngComputeGlyphSet': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("FD_GLYPHSET", SimStruct), offset=0), arg_names=["nCodePage", "nFirstChar", "cChars"]),
        #
        'EngMultiByteToWideChar': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "WideCharString", "BytesInWideCharString", "MultiByteString", "BytesInMultiByteString"]),
        #
        'EngWideCharToMultiByte': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "WideCharString", "BytesInWideCharString", "MultiByteString", "BytesInMultiByteString"]),
        #
        'EngGetCurrentCodePage': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["OemCodePage", "AnsiCodePage"]),
        #
        'EngQueryEMFInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("EMFINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdev", "pEMFInfo"]),
        #
        'GetTextCharset': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetTextCharsetInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FONTSIGNATURE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpSig", "dwFlags"]),
        #
        'TranslateCharsetInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CHARSETINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="TRANSLATE_CHARSET_INFO_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSrc", "lpCs", "dwFlags"]),
        #
        'GetObjectA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["h", "c", "pv"]),
        #
        'AddFontResourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'AddFontResourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'AnimatePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPal", "iStartIndex", "cEntries", "ppe"]),
        #
        'Arc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'BitBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ROP_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "cx", "cy", "hdcSrc", "x1", "y1", "rop"]),
        #
        'CancelDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'Chord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'CloseMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'CombineRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RGN_COMBINE_MODE")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hrgnDst", "hrgnSrc1", "hrgnSrc2", "iMode"]),
        #
        'CopyMetaFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'CopyMetaFileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'CreateBitmap': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nWidth", "nHeight", "nPlanes", "nBitCount", "lpBits"]),
        #
        'CreateBitmapIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAP", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbm"]),
        #
        'CreateBrushIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("LOGBRUSH", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["plbrush"]),
        #
        'CreateCompatibleBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "cx", "cy"]),
        #
        'CreateDiscardableBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "cx", "cy"]),
        #
        'CreateCompatibleDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'CreateDCA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszDriver", "pwszDevice", "pszPort", "pdm"]),
        #
        'CreateDCW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszDriver", "pwszDevice", "pszPort", "pdm"]),
        #
        'CreateDIBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "pbmih", "flInit", "pjBits", "pbmi", "iUsage"]),
        #
        'CreateDIBPatternBrush': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["h", "iUsage"]),
        #
        'CreateDIBPatternBrushPt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPackedDIB", "iUsage"]),
        #
        'CreateEllipticRgn': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'CreateEllipticRgnIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lprect"]),
        #
        'CreateFontIndirectA': SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lplf"]),
        #
        'CreateFontIndirectW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lplf"]),
        #
        'CreateFontA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["cHeight", "cWidth", "cEscapement", "cOrientation", "cWeight", "bItalic", "bUnderline", "bStrikeOut", "iCharSet", "iOutPrecision", "iClipPrecision", "iQuality", "iPitchAndFamily", "pszFaceName"]),
        #
        'CreateFontW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["cHeight", "cWidth", "cEscapement", "cOrientation", "cWeight", "bItalic", "bUnderline", "bStrikeOut", "iCharSet", "iOutPrecision", "iClipPrecision", "iQuality", "iPitchAndFamily", "pszFaceName"]),
        #
        'CreateHatchBrush': SimTypeFunction([SimTypeInt(signed=False, label="HATCH_BRUSH_STYLE"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["iHatch", "color"]),
        #
        'CreateICA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszDriver", "pszDevice", "pszPort", "pdm"]),
        #
        'CreateICW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszDriver", "pszDevice", "pszPort", "pdm"]),
        #
        'CreateMetaFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszFile"]),
        #
        'CreateMetaFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszFile"]),
        #
        'CreatePalette': SimTypeFunction([SimTypePointer(SimTypeRef("LOGPALETTE", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["plpal"]),
        #
        'CreatePen': SimTypeFunction([SimTypeInt(signed=False, label="PEN_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["iStyle", "cWidth", "color"]),
        #
        'CreatePenIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("LOGPEN", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["plpen"]),
        #
        'CreatePolyPolygonRgn': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="CREATE_POLYGON_RGN_MODE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pptl", "pc", "cPoly", "iMode"]),
        #
        'CreatePatternBrush': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hbm"]),
        #
        'CreateRectRgn': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'CreateRectRgnIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lprect"]),
        #
        'CreateRoundRectRgn': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["x1", "y1", "x2", "y2", "w", "h"]),
        #
        'CreateScalableFontResourceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fdwHidden", "lpszFont", "lpszFile", "lpszPath"]),
        #
        'CreateScalableFontResourceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fdwHidden", "lpszFont", "lpszFile", "lpszPath"]),
        #
        'CreateSolidBrush': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["color"]),
        #
        'DeleteDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'DeleteMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmf"]),
        #
        'DeleteObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ho"]),
        #
        'DrawEscape': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iEscape", "cjIn", "lpIn"]),
        #
        'Ellipse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "left", "top", "right", "bottom"]),
        #
        'EnumFontFamiliesExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam", "dwFlags"]),
        #
        'EnumFontFamiliesExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam", "dwFlags"]),
        #
        'EnumFontFamiliesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam"]),
        #
        'EnumFontFamiliesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam"]),
        #
        'EnumFontsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam"]),
        #
        'EnumFontsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0), SimTypePointer(SimTypeRef("TEXTMETRICW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpLogfont", "lpProc", "lParam"]),
        #
        'EnumObjects': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJ_TYPE"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "nType", "lpFunc", "lParam"]),
        #
        'EqualRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrgn1", "hrgn2"]),
        #
        'ExcludeClipRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "left", "top", "right", "bottom"]),
        #
        'ExtCreateRegion': SimTypeFunction([SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpx", "nCount", "lpData"]),
        #
        'ExtFloodFill': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="EXT_FLOOD_FILL_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "color", "type"]),
        #
        'FillRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn", "hbr"]),
        #
        'FloodFill': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "color"]),
        #
        'FrameRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn", "hbr", "w", "h"]),
        #
        'GetROP2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="R2_MODE"), arg_names=["hdc"]),
        #
        'GetAspectRatioFilterEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpsize"]),
        #
        'GetBkColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetDCBrushColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetDCPenColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetBkMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetBitmapBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbit", "cb", "lpvBits"]),
        #
        'GetBitmapDimensionEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbit", "lpsize"]),
        #
        'GetBoundsRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lprect", "flags"]),
        #
        'GetBrushOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppt"]),
        #
        'GetCharWidthA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharWidthW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharWidth32A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharWidth32W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharWidthFloatA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharWidthFloatW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpBuffer"]),
        #
        'GetCharABCWidthsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ABC", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "wFirst", "wLast", "lpABC"]),
        #
        'GetCharABCWidthsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ABC", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "wFirst", "wLast", "lpABC"]),
        #
        'GetCharABCWidthsFloatA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ABCFLOAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpABC"]),
        #
        'GetCharABCWidthsFloatW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ABCFLOAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iFirst", "iLast", "lpABC"]),
        #
        'GetClipBox': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "lprect"]),
        #
        'GetClipRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn"]),
        #
        'GetMetaRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn"]),
        #
        'GetCurrentObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "type"]),
        #
        'GetCurrentPositionEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppt"]),
        #
        'GetDeviceCaps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "index"]),
        #
        'GetDIBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hbm", "start", "cLines", "lpvBits", "lpbmi", "usage"]),
        #
        'GetFontData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "dwTable", "dwOffset", "pvBuffer", "cjBuffer"]),
        #
        'GetGlyphOutlineA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_GLYPH_OUTLINE_FORMAT"), SimTypePointer(SimTypeRef("GLYPHMETRICS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MAT2", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "uChar", "fuFormat", "lpgm", "cjBuffer", "pvBuffer", "lpmat2"]),
        #
        'GetGlyphOutlineW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_GLYPH_OUTLINE_FORMAT"), SimTypePointer(SimTypeRef("GLYPHMETRICS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MAT2", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "uChar", "fuFormat", "lpgm", "cjBuffer", "pvBuffer", "lpmat2"]),
        #
        'GetGraphicsMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetMapMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="HDC_MAP_MODE"), arg_names=["hdc"]),
        #
        'GetMetaFileBitsEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMF", "cbBuffer", "lpData"]),
        #
        'GetMetaFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName"]),
        #
        'GetMetaFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName"]),
        #
        'GetNearestColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "color"]),
        #
        'GetNearestPaletteIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["h", "color"]),
        #
        'GetObjectType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["h"]),
        #
        'GetOutlineTextMetricsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OUTLINETEXTMETRICA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "cjCopy", "potm"]),
        #
        'GetOutlineTextMetricsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OUTLINETEXTMETRICW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "cjCopy", "potm"]),
        #
        'GetPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hpal", "iStart", "cEntries", "pPalEntries"]),
        #
        'GetPixel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "x", "y"]),
        #
        'GetPolyFillMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetRasterizerCaps': SimTypeFunction([SimTypePointer(SimTypeRef("RASTERIZER_STATUS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpraststat", "cjBytes"]),
        #
        'GetRandomRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn", "i"]),
        #
        'GetRegionData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hrgn", "nCount", "lpRgnData"]),
        #
        'GetRgnBox': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hrgn", "lprc"]),
        #
        'GetStockObject': SimTypeFunction([SimTypeInt(signed=False, label="GET_STOCK_OBJECT_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["i"]),
        #
        'GetStretchBltMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetSystemPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "iStart", "cEntries", "pPalEntries"]),
        #
        'GetSystemPaletteUse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetTextCharacterExtra': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetTextAlign': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="TEXT_ALIGN_OPTIONS"), arg_names=["hdc"]),
        #
        'GetTextColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetTextExtentPointA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpString", "c", "lpsz"]),
        #
        'GetTextExtentPointW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpString", "c", "lpsz"]),
        #
        'GetTextExtentPoint32A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpString", "c", "psizl"]),
        #
        'GetTextExtentPoint32W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpString", "c", "psizl"]),
        #
        'GetTextExtentExPointA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpszString", "cchString", "nMaxExtent", "lpnFit", "lpnDx", "lpSize"]),
        #
        'GetTextExtentExPointW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpszString", "cchString", "nMaxExtent", "lpnFit", "lpnDx", "lpSize"]),
        #
        'GetFontLanguageInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'GetCharacterPlacementA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("GCP_RESULTSA", SimStruct), offset=0), SimTypeInt(signed=False, label="GET_CHARACTER_PLACEMENT_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpString", "nCount", "nMexExtent", "lpResults", "dwFlags"]),
        #
        'GetCharacterPlacementW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("GCP_RESULTSW", SimStruct), offset=0), SimTypeInt(signed=False, label="GET_CHARACTER_PLACEMENT_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpString", "nCount", "nMexExtent", "lpResults", "dwFlags"]),
        #
        'GetFontUnicodeRanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GLYPHSET", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpgs"]),
        #
        'GetGlyphIndicesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpstr", "c", "pgi", "fl"]),
        #
        'GetGlyphIndicesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpstr", "c", "pgi", "fl"]),
        #
        'GetTextExtentPointI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pgiIn", "cgi", "psize"]),
        #
        'GetTextExtentExPointI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpwszString", "cwchString", "nMaxExtent", "lpnFit", "lpnDx", "lpSize"]),
        #
        'GetCharWidthI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "giFirst", "cgi", "pgi", "piWidths"]),
        #
        'GetCharABCWidthsI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ABC", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "giFirst", "cgi", "pgi", "pabc"]),
        #
        'AddFontResourceExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FONT_RESOURCE_CHARACTERISTICS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "fl", "res"]),
        #
        'AddFontResourceExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FONT_RESOURCE_CHARACTERISTICS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "fl", "res"]),
        #
        'RemoveFontResourceExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "fl", "pdv"]),
        #
        'RemoveFontResourceExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "fl", "pdv"]),
        #
        'AddFontMemResourceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pFileView", "cjSize", "pvResrved", "pNumFonts"]),
        #
        'RemoveFontMemResourceEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["h"]),
        #
        'CreateFontIndirectExA': SimTypeFunction([SimTypePointer(SimTypeRef("ENUMLOGFONTEXDVA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'CreateFontIndirectExW': SimTypeFunction([SimTypePointer(SimTypeRef("ENUMLOGFONTEXDVW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'GetViewportExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpsize"]),
        #
        'GetViewportOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppoint"]),
        #
        'GetWindowExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpsize"]),
        #
        'GetWindowOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppoint"]),
        #
        'IntersectClipRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "left", "top", "right", "bottom"]),
        #
        'InvertRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn"]),
        #
        'LineDDA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["xStart", "yStart", "xEnd", "yEnd", "lpProc", "data"]),
        #
        'LineTo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y"]),
        #
        'MaskBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xDest", "yDest", "width", "height", "hdcSrc", "xSrc", "ySrc", "hbmMask", "xMask", "yMask", "rop"]),
        #
        'PlgBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "lpPoint", "hdcSrc", "xSrc", "ySrc", "width", "height", "hbmMask", "xMask", "yMask"]),
        #
        'OffsetClipRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "x", "y"]),
        #
        'OffsetRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hrgn", "x", "y"]),
        #
        'PatBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ROP_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "w", "h", "rop"]),
        #
        'Pie': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "left", "top", "right", "bottom", "xr1", "yr1", "xr2", "yr2"]),
        #
        'PlayMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hmf"]),
        #
        'PaintRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hrgn"]),
        #
        'PolyPolygon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "asz", "csz"]),
        #
        'PtInRegion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hrgn", "x", "y"]),
        #
        'PtVisible': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y"]),
        #
        'RectInRegion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrgn", "lprect"]),
        #
        'RectVisible': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lprect"]),
        #
        'Rectangle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "left", "top", "right", "bottom"]),
        #
        'RestoreDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "nSavedDC"]),
        #
        'ResetDCA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "lpdm"]),
        #
        'ResetDCW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "lpdm"]),
        #
        'RealizePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'RemoveFontResourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'RemoveFontResourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'RoundRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "left", "top", "right", "bottom", "width", "height"]),
        #
        'ResizePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hpal", "n"]),
        #
        'SaveDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'SelectClipRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "hrgn"]),
        #
        'ExtSelectClipRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RGN_COMBINE_MODE")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc", "hrgn", "mode"]),
        #
        'SetMetaRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hdc"]),
        #
        'SelectObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "h"]),
        #
        'SelectPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "hPal", "bForceBkgd"]),
        #
        'SetBkColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "color"]),
        #
        'SetDCBrushColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "color"]),
        #
        'SetDCPenColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "color"]),
        #
        'SetBkMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "mode"]),
        #
        'SetBitmapBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbm", "cb", "pvBits"]),
        #
        'SetBoundsRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="SET_BOUNDS_RECT_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lprect", "flags"]),
        #
        'SetDIBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hbm", "start", "cLines", "lpBits", "lpbmi", "ColorUse"]),
        #
        'SetDIBitsToDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "xDest", "yDest", "w", "h", "xSrc", "ySrc", "StartScan", "cLines", "lpvBits", "lpbmi", "ColorUse"]),
        #
        'SetMapperFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "flags"]),
        #
        'SetGraphicsMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GRAPHICS_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iMode"]),
        #
        'SetMapMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HDC_MAP_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iMode"]),
        #
        'SetLayout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DC_LAYOUT")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "l"]),
        #
        'GetLayout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc"]),
        #
        'SetMetaFileBitsEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["cbBuffer", "lpData"]),
        #
        'SetPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hpal", "iStart", "cEntries", "pPalEntries"]),
        #
        'SetPixel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "x", "y", "color"]),
        #
        'SetPixelV': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "color"]),
        #
        'SetPolyFillMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CREATE_POLYGON_RGN_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "mode"]),
        #
        'StretchBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ROP_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xDest", "yDest", "wDest", "hDest", "hdcSrc", "xSrc", "ySrc", "wSrc", "hSrc", "rop"]),
        #
        'SetRectRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hrgn", "left", "top", "right", "bottom"]),
        #
        'StretchDIBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE"), SimTypeInt(signed=False, label="ROP_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "xDest", "yDest", "DestWidth", "DestHeight", "xSrc", "ySrc", "SrcWidth", "SrcHeight", "lpBits", "lpbmi", "iUsage", "rop"]),
        #
        'SetROP2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="R2_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "rop2"]),
        #
        'SetStretchBltMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="STRETCH_BLT_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "mode"]),
        #
        'SetSystemPaletteUse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SYSTEM_PALETTE_USE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "use"]),
        #
        'SetTextCharacterExtra': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "extra"]),
        #
        'SetTextColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "color"]),
        #
        'SetTextAlign': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TEXT_ALIGN_OPTIONS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "align"]),
        #
        'SetTextJustification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "extra", "count"]),
        #
        'UpdateColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GdiAlphaBlend': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeRef("BLENDFUNCTION", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xoriginDest", "yoriginDest", "wDest", "hDest", "hdcSrc", "xoriginSrc", "yoriginSrc", "wSrc", "hSrc", "ftn"]),
        #
        'GdiTransparentBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xoriginDest", "yoriginDest", "wDest", "hDest", "hdcSrc", "xoriginSrc", "yoriginSrc", "wSrc", "hSrc", "crTransparent"]),
        #
        'GdiGradientFill': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TRIVERTEX", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GRADIENT_FILL")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pVertex", "nVertex", "pMesh", "nCount", "ulMode"]),
        #
        'PlayMetaFileRecord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HANDLETABLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("METARECORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpHandleTable", "lpMR", "noObjs"]),
        #
        'EnumMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HANDLETABLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("METARECORD", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpht", "lpMR", "nObj", "param4"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hmf", "proc", "param3"]),
        #
        'CloseEnhMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'CopyEnhMetaFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hEnh", "lpFileName"]),
        #
        'CopyEnhMetaFileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hEnh", "lpFileName"]),
        #
        'CreateEnhMetaFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "lpFilename", "lprc", "lpDesc"]),
        #
        'CreateEnhMetaFileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "lpFilename", "lprc", "lpDesc"]),
        #
        'DeleteEnhMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmf"]),
        #
        'EnumEnhMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HANDLETABLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ENHMETARECORD", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpht", "lpmr", "nHandles", "data"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hmf", "proc", "param3", "lpRect"]),
        #
        'GetEnhMetaFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName"]),
        #
        'GetEnhMetaFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName"]),
        #
        'GetEnhMetaFileBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEMF", "nSize", "lpData"]),
        #
        'GetEnhMetaFileDescriptionA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "cchBuffer", "lpDescription"]),
        #
        'GetEnhMetaFileDescriptionW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "cchBuffer", "lpDescription"]),
        #
        'GetEnhMetaFileHeader': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ENHMETAHEADER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "nSize", "lpEnhMetaHeader"]),
        #
        'GetEnhMetaFilePaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "nNumEntries", "lpPaletteEntries"]),
        #
        'GetWinMetaFileBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "cbData16", "pData16", "iMapMode", "hdcRef"]),
        #
        'PlayEnhMetaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hmf", "lprect"]),
        #
        'PlayEnhMetaFileRecord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HANDLETABLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ENHMETARECORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pht", "pmr", "cht"]),
        #
        'SetEnhMetaFileBits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nSize", "pb"]),
        #
        'GdiComment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "nSize", "lpData"]),
        #
        'GetTextMetricsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TEXTMETRICA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lptm"]),
        #
        'GetTextMetricsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TEXTMETRICW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lptm"]),
        #
        'AngleArc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "r", "StartAngle", "SweepAngle"]),
        #
        'PolyPolyline': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "asz", "csz"]),
        #
        'GetWorldTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpxf"]),
        #
        'SetWorldTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpxf"]),
        #
        'ModifyWorldTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0), SimTypeInt(signed=False, label="MODIFY_WORLD_TRANSFORM_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpxf", "mode"]),
        #
        'CombineTransform': SimTypeFunction([SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0), SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0), SimTypePointer(SimTypeRef("XFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpxfOut", "lpxf1", "lpxf2"]),
        #
        'CreateDIBSection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="DIB_USAGE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "pbmi", "usage", "ppvBits", "hSection", "offset"]),
        #
        'GetDIBColorTable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "iStart", "cEntries", "prgbq"]),
        #
        'SetDIBColorTable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "iStart", "cEntries", "prgbq"]),
        #
        'SetColorAdjustment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COLORADJUSTMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpca"]),
        #
        'GetColorAdjustment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COLORADJUSTMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpca"]),
        #
        'CreateHalftonePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'AbortPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'ArcTo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "left", "top", "right", "bottom", "xr1", "yr1", "xr2", "yr2"]),
        #
        'BeginPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'CloseFigure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'EndPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'FillPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'FlattenPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "aj", "cpt"]),
        #
        'PathToRegion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'PolyDraw': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "aj", "cpt"]),
        #
        'SelectClipPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RGN_COMBINE_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "mode"]),
        #
        'SetArcDirection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ARC_DIRECTION")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "dir"]),
        #
        'SetMiterLimit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "limit", "old"]),
        #
        'StrokeAndFillPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'StrokePath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'WidenPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'ExtCreatePen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LOGBRUSH", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["iPenStyle", "cWidth", "plbrush", "cStyle", "pstyle"]),
        #
        'GetMiterLimit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "plimit"]),
        #
        'GetArcDirection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'GetObjectW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["h", "c", "pv"]),
        #
        'MoveToEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'TextOutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpString", "c"]),
        #
        'TextOutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpString", "c"]),
        #
        'ExtTextOutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ETO_OPTIONS"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "options", "lprect", "lpString", "c", "lpDx"]),
        #
        'ExtTextOutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ETO_OPTIONS"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "options", "lprect", "lpString", "c", "lpDx"]),
        #
        'PolyTextOutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POLYTEXTA", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "ppt", "nstrings"]),
        #
        'PolyTextOutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POLYTEXTW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "ppt", "nstrings"]),
        #
        'CreatePolygonRgn': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="CREATE_POLYGON_RGN_MODE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pptl", "cPoint", "iMode"]),
        #
        'DPtoLP': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppt", "c"]),
        #
        'LPtoDP': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppt", "c"]),
        #
        'Polygon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "cpt"]),
        #
        'Polyline': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "cpt"]),
        #
        'PolyBezier': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "cpt"]),
        #
        'PolyBezierTo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "cpt"]),
        #
        'PolylineTo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "apt", "cpt"]),
        #
        'SetViewportExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpsz"]),
        #
        'SetViewportOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'SetWindowExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpsz"]),
        #
        'SetWindowOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'OffsetViewportOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'OffsetWindowOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'ScaleViewportExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "xn", "dx", "yn", "yd", "lpsz"]),
        #
        'ScaleWindowExtEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "xn", "xd", "yn", "yd", "lpsz"]),
        #
        'SetBitmapDimensionEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbm", "w", "h", "lpsz"]),
        #
        'SetBrushOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lppt"]),
        #
        'GetTextFaceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "c", "lpName"]),
        #
        'GetTextFaceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "c", "lpName"]),
        #
        'GetKerningPairsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("KERNINGPAIR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "nPairs", "lpKernPair"]),
        #
        'GetKerningPairsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("KERNINGPAIR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "nPairs", "lpKernPair"]),
        #
        'GetDCOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lppt"]),
        #
        'FixBrushOrgEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "ptl"]),
        #
        'UnrealizeObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["h"]),
        #
        'GdiFlush': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GdiSetBatchLimit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dw"]),
        #
        'GdiGetBatchLimit': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ChoosePixelFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PIXELFORMATDESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "ppfd"]),
        #
        'DescribePixelFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PIXELFORMATDESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iPixelFormat", "nBytes", "ppfd"]),
        #
        'GetPixelFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'SetPixelFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("PIXELFORMATDESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "format", "ppfd"]),
        #
        'GetEnhMetaFilePixelFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PIXELFORMATDESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "cbBuffer", "ppfd"]),
        #
        'SwapBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GdiGetSpoolFileHandle': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszPrinterName", "pDevmode", "pwszDocName"]),
        #
        'GdiDeleteSpoolFileHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle"]),
        #
        'GdiGetPageCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SpoolFileHandle"]),
        #
        'GdiGetDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["SpoolFileHandle"]),
        #
        'GdiGetPageHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["SpoolFileHandle", "Page", "pdwPageType"]),
        #
        'GdiStartDocEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DOCINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle", "pDocInfo"]),
        #
        'GdiStartPageEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle"]),
        #
        'GdiPlayPageEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle", "hemf", "prectDocument", "prectBorder", "prectClip"]),
        #
        'GdiEndPageEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle", "dwOptimization"]),
        #
        'GdiEndDocEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle"]),
        #
        'GdiGetDevmodeForPage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle", "dwPageNumber", "pCurrDM", "pLastDM"]),
        #
        'GdiResetDCEMF': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SpoolFileHandle", "pCurrDM"]),
        #
        'Escape': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iEscape", "cjIn", "pvIn", "pvOut"]),
        #
        'ExtEscape': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "iEscape", "cjInput", "lpInData", "cjOutput", "lpOutData"]),
        #
        'StartDocA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DOCINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpdi"]),
        #
        'StartDocW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DOCINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpdi"]),
        #
        'EndDoc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'StartPage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'EndPage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'AbortDoc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'SetAbortProc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "proc"]),
        #
        'SetWinMetaFileBits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("METAFILEPICT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nSize", "lpMeta16Data", "hdcRef", "lpMFP"]),
        #
        'SetICMMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ICM_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "mode"]),
        #
        'CheckColorsInGamut': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RGBTRIPLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpRGBTriple", "dlpBuffer", "nCount"]),
        #
        'GetColorSpace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        #
        'GetLogColorSpaceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorSpace", "lpBuffer", "nSize"]),
        #
        'GetLogColorSpaceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorSpace", "lpBuffer", "nSize"]),
        #
        'CreateColorSpaceA': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lplcs"]),
        #
        'CreateColorSpaceW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lplcs"]),
        #
        'SetColorSpace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc", "hcs"]),
        #
        'DeleteColorSpace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hcs"]),
        #
        'GetICMProfileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pBufSize", "pszFilename"]),
        #
        'GetICMProfileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pBufSize", "pszFilename"]),
        #
        'SetICMProfileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpFileName"]),
        #
        'SetICMProfileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpFileName"]),
        #
        'GetDeviceGammaRamp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpRamp"]),
        #
        'SetDeviceGammaRamp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpRamp"]),
        #
        'ColorMatchToTarget': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="COLOR_MATCH_TO_TARGET_ACTION")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hdcTarget", "action"]),
        #
        'EnumICMProfilesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "proc", "param2"]),
        #
        'EnumICMProfilesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "proc", "param2"]),
        #
        'UpdateICMRegKeyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="ICM_COMMAND")], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "lpszCMID", "lpszFileName", "command"]),
        #
        'UpdateICMRegKeyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ICM_COMMAND")], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "lpszCMID", "lpszFileName", "command"]),
        #
        'ColorCorrectPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hPal", "deFirst", "num"]),
    }

lib.set_prototypes(prototypes)
