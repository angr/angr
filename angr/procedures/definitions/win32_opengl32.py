# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("opengl32.dll")
prototypes = \
    {
        #
        'wglSwapMultipleBuffers': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"hdc": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "uiFlags": SimTypeInt(signed=False, label="UInt32")}, name="WGLSWAP", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1"]),
        #
        'wglCopyContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]),
        #
        'wglCreateContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'wglCreateLayerContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'wglDeleteContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'wglGetCurrentContext': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'wglGetCurrentDC': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'wglGetProcAddress': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0), arg_names=["param0"]),
        #
        'wglMakeCurrent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'wglShareLists': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'wglUseFontBitmapsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'wglUseFontBitmapsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'wglUseFontOutlinesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimStruct({"gmfBlackBoxX": SimTypeFloat(size=32), "gmfBlackBoxY": SimTypeFloat(size=32), "gmfptGlyphOrigin": SimStruct({"x": SimTypeFloat(size=32), "y": SimTypeFloat(size=32)}, name="POINTFLOAT", pack=False, align=None), "gmfCellIncX": SimTypeFloat(size=32), "gmfCellIncY": SimTypeFloat(size=32)}, name="GLYPHMETRICSFLOAT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'wglUseFontOutlinesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimStruct({"gmfBlackBoxX": SimTypeFloat(size=32), "gmfBlackBoxY": SimTypeFloat(size=32), "gmfptGlyphOrigin": SimStruct({"x": SimTypeFloat(size=32), "y": SimTypeFloat(size=32)}, name="POINTFLOAT", pack=False, align=None), "gmfCellIncX": SimTypeFloat(size=32), "gmfCellIncY": SimTypeFloat(size=32)}, name="GLYPHMETRICSFLOAT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'wglDescribeLayerPlane': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"nSize": SimTypeShort(signed=False, label="UInt16"), "nVersion": SimTypeShort(signed=False, label="UInt16"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "iPixelType": SimTypeChar(label="Byte"), "cColorBits": SimTypeChar(label="Byte"), "cRedBits": SimTypeChar(label="Byte"), "cRedShift": SimTypeChar(label="Byte"), "cGreenBits": SimTypeChar(label="Byte"), "cGreenShift": SimTypeChar(label="Byte"), "cBlueBits": SimTypeChar(label="Byte"), "cBlueShift": SimTypeChar(label="Byte"), "cAlphaBits": SimTypeChar(label="Byte"), "cAlphaShift": SimTypeChar(label="Byte"), "cAccumBits": SimTypeChar(label="Byte"), "cAccumRedBits": SimTypeChar(label="Byte"), "cAccumGreenBits": SimTypeChar(label="Byte"), "cAccumBlueBits": SimTypeChar(label="Byte"), "cAccumAlphaBits": SimTypeChar(label="Byte"), "cDepthBits": SimTypeChar(label="Byte"), "cStencilBits": SimTypeChar(label="Byte"), "cAuxBuffers": SimTypeChar(label="Byte"), "iLayerPlane": SimTypeChar(label="Byte"), "bReserved": SimTypeChar(label="Byte"), "crTransparent": SimTypeInt(signed=False, label="UInt32")}, name="LAYERPLANEDESCRIPTOR", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglSetLayerPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglGetLayerPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglRealizeLayerPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]),
        #
        'wglSwapLayerBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
    }

lib.set_prototypes(prototypes)
