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
lib.set_library_names("glu32.dll")
prototypes = \
    {
        #
        'gluErrorString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["errCode"]),
        #
        'gluErrorUnicodeStringEXT': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["errCode"]),
        #
        'gluGetString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["name"]),
        #
        'gluOrtho2D': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["left", "right", "bottom", "top"]),
        #
        'gluPerspective': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["fovy", "aspect", "zNear", "zFar"]),
        #
        'gluPickMatrix': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["x", "y", "width", "height", "viewport"]),
        #
        'gluLookAt': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["eyex", "eyey", "eyez", "centerx", "centery", "centerz", "upx", "upy", "upz"]),
        #
        'gluProject': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["objx", "objy", "objz", "modelMatrix", "projMatrix", "viewport", "winx", "winy", "winz"]),
        #
        'gluUnProject': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["winx", "winy", "winz", "modelMatrix", "projMatrix", "viewport", "objx", "objy", "objz"]),
        #
        'gluScaleImage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "widthin", "heightin", "typein", "datain", "widthout", "heightout", "typeout", "dataout"]),
        #
        'gluBuild1DMipmaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["target", "components", "width", "format", "type", "data"]),
        #
        'gluBuild2DMipmaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["target", "components", "width", "height", "format", "type", "data"]),
        #
        'gluNewQuadric': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)),
        #
        'gluDeleteQuadric': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["state"]),
        #
        'gluQuadricNormals': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["quadObject", "normals"]),
        #
        'gluQuadricTexture': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["quadObject", "textureCoords"]),
        #
        'gluQuadricOrientation': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["quadObject", "orientation"]),
        #
        'gluQuadricDrawStyle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["quadObject", "drawStyle"]),
        #
        'gluCylinder': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["qobj", "baseRadius", "topRadius", "height", "slices", "stacks"]),
        #
        'gluDisk': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["qobj", "innerRadius", "outerRadius", "slices", "loops"]),
        #
        'gluPartialDisk': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["qobj", "innerRadius", "outerRadius", "slices", "loops", "startAngle", "sweepAngle"]),
        #
        'gluSphere': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["qobj", "radius", "slices", "stacks"]),
        #
        'gluQuadricCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["qobj", "which", "fn"]),
        #
        'gluNewTess': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)),
        #
        'gluDeleteTess': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
        #
        'gluTessBeginPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess", "polygon_data"]),
        #
        'gluTessBeginContour': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
        #
        'gluTessVertex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess", "coords", "data"]),
        #
        'gluTessEndContour': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
        #
        'gluTessEndPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
        #
        'gluTessProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["tess", "which", "value"]),
        #
        'gluTessNormal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["tess", "x", "y", "z"]),
        #
        'gluTessCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["tess", "which", "fn"]),
        #
        'gluGetTessProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess", "which", "value"]),
        #
        'gluNewNurbsRenderer': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)),
        #
        'gluDeleteNurbsRenderer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluBeginSurface': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluBeginCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluEndCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluEndSurface': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluBeginTrim': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluEndTrim': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj"]),
        #
        'gluPwlCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["nobj", "count", "array", "stride", "type"]),
        #
        'gluNurbsCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["nobj", "nknots", "knot", "stride", "ctlarray", "order", "type"]),
        #
        'gluNurbsSurface': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["nobj", "sknot_count", "sknot", "tknot_count", "tknot", "s_stride", "t_stride", "ctlarray", "sorder", "torder", "type"]),
        #
        'gluLoadSamplingMatrices': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj", "modelMatrix", "projMatrix", "viewport"]),
        #
        'gluNurbsProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32)], SimTypeBottom(label="Void"), arg_names=["nobj", "property", "value"]),
        #
        'gluGetNurbsProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj", "property", "value"]),
        #
        'gluNurbsCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["nobj", "which", "fn"]),
        #
        'gluBeginPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
        #
        'gluNextContour': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["tess", "type"]),
        #
        'gluEndPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["tess"]),
    }

lib.set_prototypes(prototypes)
