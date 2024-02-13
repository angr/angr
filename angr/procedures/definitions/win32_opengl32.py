# pylint:disable=line-too-long
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
lib.set_library_names("opengl32.dll")
prototypes = \
    {
        #
        'wglSwapMultipleBuffers': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WGLSWAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1"]),
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
        'wglUseFontOutlinesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("GLYPHMETRICSFLOAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'wglUseFontOutlinesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("GLYPHMETRICSFLOAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'wglDescribeLayerPlane': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LAYERPLANEDESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglSetLayerPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglGetLayerPaletteEntries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'wglRealizeLayerPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]),
        #
        'wglSwapLayerBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'glAccum': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["op", "value"]),
        #
        'glAlphaFunc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["func", "ref"]),
        #
        'glAreTexturesResident': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["n", "textures", "residences"]),
        #
        'glArrayElement': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["i"]),
        #
        'glBegin': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glBindTexture': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["target", "texture"]),
        #
        'glBitmap': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["width", "height", "xorig", "yorig", "xmove", "ymove", "bitmap"]),
        #
        'glBlendFunc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["sfactor", "dfactor"]),
        #
        'glCallList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["list"]),
        #
        'glCallLists': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["n", "type", "lists"]),
        #
        'glClear': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glClearAccum': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glClearColor': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glClearDepth': SimTypeFunction([SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["depth"]),
        #
        'glClearIndex': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glClearStencil': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["s"]),
        #
        'glClipPlane': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["plane", "equation"]),
        #
        'glColor3b': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3bv': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3ub': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3ubv': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3ui': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3uiv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor3us': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue"]),
        #
        'glColor3usv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4b': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4bv': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4ub': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4ubv': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4ui': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4uiv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColor4us': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColor4usv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glColorMask': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["red", "green", "blue", "alpha"]),
        #
        'glColorMaterial': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["face", "mode"]),
        #
        'glColorPointer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["size", "type", "stride", "pointer"]),
        #
        'glCopyPixels': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "width", "height", "type"]),
        #
        'glCopyTexImage1D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "level", "internalFormat", "x", "y", "width", "border"]),
        #
        'glCopyTexImage2D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "level", "internalFormat", "x", "y", "width", "height", "border"]),
        #
        'glCopyTexSubImage1D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "level", "xoffset", "x", "y", "width"]),
        #
        'glCopyTexSubImage2D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "level", "xoffset", "yoffset", "x", "y", "width", "height"]),
        #
        'glCullFace': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glDeleteLists': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["list", "range"]),
        #
        'glDeleteTextures': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["n", "textures"]),
        #
        'glDepthFunc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["func"]),
        #
        'glDepthMask': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["flag"]),
        #
        'glDepthRange': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["zNear", "zFar"]),
        #
        'glDisable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["cap"]),
        #
        'glDisableClientState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["array"]),
        #
        'glDrawArrays': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["mode", "first", "count"]),
        #
        'glDrawBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glDrawElements': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["mode", "count", "type", "indices"]),
        #
        'glDrawPixels': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["width", "height", "format", "type", "pixels"]),
        #
        'glEdgeFlag': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["flag"]),
        #
        'glEdgeFlagPointer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["stride", "pointer"]),
        #
        'glEdgeFlagv': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["flag"]),
        #
        'glEnable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["cap"]),
        #
        'glEnableClientState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["array"]),
        #
        'glEnd': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glEndList': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glEvalCoord1d': SimTypeFunction([SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalCoord1dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalCoord1f': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalCoord1fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalCoord2d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["u", "v"]),
        #
        'glEvalCoord2dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalCoord2f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["u", "v"]),
        #
        'glEvalCoord2fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["u"]),
        #
        'glEvalMesh1': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["mode", "i1", "i2"]),
        #
        'glEvalMesh2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["mode", "i1", "i2", "j1", "j2"]),
        #
        'glEvalPoint1': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["i"]),
        #
        'glEvalPoint2': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["i", "j"]),
        #
        'glFeedbackBuffer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["size", "type", "buffer"]),
        #
        'glFinish': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glFlush': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glFogf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glFogfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glFogi': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glFogiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glFrontFace': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glFrustum': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["left", "right", "bottom", "top", "zNear", "zFar"]),
        #
        'glGenLists': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["range"]),
        #
        'glGenTextures': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["n", "textures"]),
        #
        'glGetBooleanv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glGetClipPlane': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["plane", "equation"]),
        #
        'glGetDoublev': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glGetError': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'glGetFloatv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glGetIntegerv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glGetLightfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["light", "pname", "params"]),
        #
        'glGetLightiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["light", "pname", "params"]),
        #
        'glGetMapdv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "query", "v"]),
        #
        'glGetMapfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "query", "v"]),
        #
        'glGetMapiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "query", "v"]),
        #
        'glGetMaterialfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["face", "pname", "params"]),
        #
        'glGetMaterialiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["face", "pname", "params"]),
        #
        'glGetPixelMapfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "values"]),
        #
        'glGetPixelMapuiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "values"]),
        #
        'glGetPixelMapusv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "values"]),
        #
        'glGetPointerv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glGetPolygonStipple': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glGetString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["name"]),
        #
        'glGetTexEnvfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glGetTexEnviv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glGetTexGendv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glGetTexGenfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glGetTexGeniv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glGetTexImage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "format", "type", "pixels"]),
        #
        'glGetTexLevelParameterfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "pname", "params"]),
        #
        'glGetTexLevelParameteriv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "pname", "params"]),
        #
        'glGetTexParameterfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glGetTexParameteriv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glHint': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["target", "mode"]),
        #
        'glIndexMask': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glIndexPointer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["type", "stride", "pointer"]),
        #
        'glIndexd': SimTypeFunction([SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexdv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexf': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexfv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexi': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexiv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexs': SimTypeFunction([SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexsv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexub': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glIndexubv': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["c"]),
        #
        'glInitNames': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glInterleavedArrays': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["format", "stride", "pointer"]),
        #
        'glIsEnabled': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["cap"]),
        #
        'glIsList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["list"]),
        #
        'glIsTexture': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["texture"]),
        #
        'glLightModelf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glLightModelfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glLightModeli': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glLightModeliv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pname", "params"]),
        #
        'glLightf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["light", "pname", "param2"]),
        #
        'glLightfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["light", "pname", "params"]),
        #
        'glLighti': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["light", "pname", "param2"]),
        #
        'glLightiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["light", "pname", "params"]),
        #
        'glLineStipple': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["factor", "pattern"]),
        #
        'glLineWidth': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["width"]),
        #
        'glListBase': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["base"]),
        #
        'glLoadIdentity': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glLoadMatrixd': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["m"]),
        #
        'glLoadMatrixf': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["m"]),
        #
        'glLoadName': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["name"]),
        #
        'glLogicOp': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["opcode"]),
        #
        'glMap1d': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "u1", "u2", "stride", "order", "points"]),
        #
        'glMap1f': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "u1", "u2", "stride", "order", "points"]),
        #
        'glMap2d': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "u1", "u2", "ustride", "uorder", "v1", "v2", "vstride", "vorder", "points"]),
        #
        'glMap2f': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "u1", "u2", "ustride", "uorder", "v1", "v2", "vstride", "vorder", "points"]),
        #
        'glMapGrid1d': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["un", "u1", "u2"]),
        #
        'glMapGrid1f': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["un", "u1", "u2"]),
        #
        'glMapGrid2d': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["un", "u1", "u2", "vn", "v1", "v2"]),
        #
        'glMapGrid2f': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["un", "u1", "u2", "vn", "v1", "v2"]),
        #
        'glMaterialf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["face", "pname", "param2"]),
        #
        'glMaterialfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["face", "pname", "params"]),
        #
        'glMateriali': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["face", "pname", "param2"]),
        #
        'glMaterialiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["face", "pname", "params"]),
        #
        'glMatrixMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glMultMatrixd': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["m"]),
        #
        'glMultMatrixf': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["m"]),
        #
        'glNewList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["list", "mode"]),
        #
        'glNormal3b': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["nx", "ny", "nz"]),
        #
        'glNormal3bv': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glNormal3d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["nx", "ny", "nz"]),
        #
        'glNormal3dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glNormal3f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["nx", "ny", "nz"]),
        #
        'glNormal3fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glNormal3i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["nx", "ny", "nz"]),
        #
        'glNormal3iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glNormal3s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["nx", "ny", "nz"]),
        #
        'glNormal3sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glNormalPointer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["type", "stride", "pointer"]),
        #
        'glOrtho': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["left", "right", "bottom", "top", "zNear", "zFar"]),
        #
        'glPassThrough': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["token"]),
        #
        'glPixelMapfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "mapsize", "values"]),
        #
        'glPixelMapuiv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "mapsize", "values"]),
        #
        'glPixelMapusv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["map", "mapsize", "values"]),
        #
        'glPixelStoref': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glPixelStorei': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glPixelTransferf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glPixelTransferi': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pname", "param1"]),
        #
        'glPixelZoom': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["xfactor", "yfactor"]),
        #
        'glPointSize': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["size"]),
        #
        'glPolygonMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["face", "mode"]),
        #
        'glPolygonOffset': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["factor", "units"]),
        #
        'glPolygonStipple': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glPopAttrib': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glPopClientAttrib': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glPopMatrix': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glPopName': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glPrioritizeTextures': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["n", "textures", "priorities"]),
        #
        'glPushAttrib': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glPushClientAttrib': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glPushMatrix': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'glPushName': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["name"]),
        #
        'glRasterPos2d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glRasterPos2dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos2f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glRasterPos2fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos2i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glRasterPos2iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos2s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glRasterPos2sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos3d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glRasterPos3dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos3f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glRasterPos3fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos3i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glRasterPos3iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos3s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glRasterPos3sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos4d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glRasterPos4dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos4f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glRasterPos4fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos4i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glRasterPos4iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glRasterPos4s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glRasterPos4sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glReadBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glReadPixels': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["x", "y", "width", "height", "format", "type", "pixels"]),
        #
        'glRectd': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'glRectdv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v1", "v2"]),
        #
        'glRectf': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'glRectfv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v1", "v2"]),
        #
        'glRecti': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'glRectiv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v1", "v2"]),
        #
        'glRects': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x1", "y1", "x2", "y2"]),
        #
        'glRectsv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v1", "v2"]),
        #
        'glRenderMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["mode"]),
        #
        'glRotated': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["angle", "x", "y", "z"]),
        #
        'glRotatef': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["angle", "x", "y", "z"]),
        #
        'glScaled': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glScalef': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glScissor': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "width", "height"]),
        #
        'glSelectBuffer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["size", "buffer"]),
        #
        'glShadeModel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mode"]),
        #
        'glStencilFunc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["func", "ref", "mask"]),
        #
        'glStencilMask': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["mask"]),
        #
        'glStencilOp': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["fail", "zfail", "zpass"]),
        #
        'glTexCoord1d': SimTypeFunction([SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["s"]),
        #
        'glTexCoord1dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord1f': SimTypeFunction([SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["s"]),
        #
        'glTexCoord1fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord1i': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["s"]),
        #
        'glTexCoord1iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord1s': SimTypeFunction([SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["s"]),
        #
        'glTexCoord1sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord2d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["s", "t"]),
        #
        'glTexCoord2dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord2f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["s", "t"]),
        #
        'glTexCoord2fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord2i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["s", "t"]),
        #
        'glTexCoord2iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord2s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["s", "t"]),
        #
        'glTexCoord2sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord3d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["s", "t", "r"]),
        #
        'glTexCoord3dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord3f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["s", "t", "r"]),
        #
        'glTexCoord3fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord3i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["s", "t", "r"]),
        #
        'glTexCoord3iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord3s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["s", "t", "r"]),
        #
        'glTexCoord3sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord4d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["s", "t", "r", "q"]),
        #
        'glTexCoord4dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord4f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["s", "t", "r", "q"]),
        #
        'glTexCoord4fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord4i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["s", "t", "r", "q"]),
        #
        'glTexCoord4iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoord4s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["s", "t", "r", "q"]),
        #
        'glTexCoord4sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glTexCoordPointer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["size", "type", "stride", "pointer"]),
        #
        'glTexEnvf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "param2"]),
        #
        'glTexEnvfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glTexEnvi': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "pname", "param2"]),
        #
        'glTexEnviv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glTexGend': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "param2"]),
        #
        'glTexGendv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glTexGenf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "param2"]),
        #
        'glTexGenfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glTexGeni': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "param2"]),
        #
        'glTexGeniv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coord", "pname", "params"]),
        #
        'glTexImage1D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "internalformat", "width", "border", "format", "type", "pixels"]),
        #
        'glTexImage2D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "internalformat", "width", "height", "border", "format", "type", "pixels"]),
        #
        'glTexParameterf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "param2"]),
        #
        'glTexParameterfv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glTexParameteri': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["target", "pname", "param2"]),
        #
        'glTexParameteriv': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "pname", "params"]),
        #
        'glTexSubImage1D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "xoffset", "width", "format", "type", "pixels"]),
        #
        'glTexSubImage2D': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["target", "level", "xoffset", "yoffset", "width", "height", "format", "type", "pixels"]),
        #
        'glTranslated': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glTranslatef': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glVertex2d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glVertex2dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex2f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glVertex2fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex2i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glVertex2iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex2s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y"]),
        #
        'glVertex2sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex3d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glVertex3dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex3f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glVertex3fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex3i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glVertex3iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex3s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z"]),
        #
        'glVertex3sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex4d': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glVertex4dv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex4f': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glVertex4fv': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex4i': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glVertex4iv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertex4s': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16"), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["x", "y", "z", "w"]),
        #
        'glVertex4sv': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["v"]),
        #
        'glVertexPointer': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["size", "type", "stride", "pointer"]),
        #
        'glViewport': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["x", "y", "width", "height"]),
    }

lib.set_prototypes(prototypes)
