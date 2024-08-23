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
lib.set_library_names("gdiplus.dll")
prototypes = \
    {
        #
        'GdipAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["size"]),
        #
        'GdipFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ptr"]),
        #
        'GdiplusStartup': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("GdiplusStartupInput", SimStruct), offset=0), SimTypePointer(SimTypeRef("GdiplusStartupOutput", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["token", "input", "output"]),
        #
        'GdiplusShutdown': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["token"]),
        #
        'GdipCreateEffect': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["guid", "effect"]),
        #
        'GdipDeleteEffect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["effect"]),
        #
        'GdipGetEffectParameterSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["effect", "size"]),
        #
        'GdipSetEffectParameters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["effect", "params", "size"]),
        #
        'GdipGetEffectParameters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["effect", "size", "params"]),
        #
        'GdipCreatePath': SimTypeFunction([SimTypeInt(signed=False, label="FillMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brushMode", "path"]),
        #
        'GdipCreatePath2': SimTypeFunction([SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FillMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["param0", "param1", "param2", "param3", "path"]),
        #
        'GdipCreatePath2I': SimTypeFunction([SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FillMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["param0", "param1", "param2", "param3", "path"]),
        #
        'GdipClonePath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "clonePath"]),
        #
        'GdipDeletePath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipResetPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipGetPointCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "count"]),
        #
        'GdipGetPathTypes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "types", "count"]),
        #
        'GdipGetPathPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["param0", "points", "count"]),
        #
        'GdipGetPathPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["param0", "points", "count"]),
        #
        'GdipGetPathFillMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="FillMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "fillmode"]),
        #
        'GdipSetPathFillMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="FillMode")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "fillmode"]),
        #
        'GdipGetPathData': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "pathData"]),
        #
        'GdipStartPathFigure': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipClosePathFigure': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipClosePathFigures': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipSetPathMarker': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipClearPathMarkers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipReversePath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path"]),
        #
        'GdipGetPathLastPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "lastPoint"]),
        #
        'GdipAddPathLine': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x1", "y1", "x2", "y2"]),
        #
        'GdipAddPathLine2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathArc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipAddPathBezier': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'GdipAddPathBeziers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathCurve2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "tension"]),
        #
        'GdipAddPathCurve3': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "offset", "numberOfSegments", "tension"]),
        #
        'GdipAddPathClosedCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathClosedCurve2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "tension"]),
        #
        'GdipAddPathRectangle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height"]),
        #
        'GdipAddPathRectangles': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "rects", "count"]),
        #
        'GdipAddPathEllipse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height"]),
        #
        'GdipAddPathPie': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipAddPathPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "addingPath", "connect"]),
        #
        'GdipAddPathString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "string", "length", "family", "style", "emSize", "layoutRect", "format"]),
        #
        'GdipAddPathStringI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "string", "length", "family", "style", "emSize", "layoutRect", "format"]),
        #
        'GdipAddPathLineI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x1", "y1", "x2", "y2"]),
        #
        'GdipAddPathLine2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathArcI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipAddPathBezierI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'GdipAddPathBeziersI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathCurveI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathCurve2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "tension"]),
        #
        'GdipAddPathCurve3I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "offset", "numberOfSegments", "tension"]),
        #
        'GdipAddPathClosedCurveI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipAddPathClosedCurve2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count", "tension"]),
        #
        'GdipAddPathRectangleI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height"]),
        #
        'GdipAddPathRectanglesI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "rects", "count"]),
        #
        'GdipAddPathEllipseI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height"]),
        #
        'GdipAddPathPieI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipAddPathPolygonI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["path", "points", "count"]),
        #
        'GdipFlattenPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "matrix", "flatness"]),
        #
        'GdipWindingModeOutline': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "matrix", "flatness"]),
        #
        'GdipWidenPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["nativePath", "pen", "matrix", "flatness"]),
        #
        'GdipWarpPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="WarpMode"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "matrix", "points", "count", "srcx", "srcy", "srcwidth", "srcheight", "warpMode", "flatness"]),
        #
        'GdipTransformPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "matrix"]),
        #
        'GdipGetPathWorldBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "bounds", "matrix", "pen"]),
        #
        'GdipGetPathWorldBoundsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "bounds", "matrix", "pen"]),
        #
        'GdipIsVisiblePathPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "graphics", "result"]),
        #
        'GdipIsVisiblePathPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "graphics", "result"]),
        #
        'GdipIsOutlineVisiblePathPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "pen", "graphics", "result"]),
        #
        'GdipIsOutlineVisiblePathPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "x", "y", "pen", "graphics", "result"]),
        #
        'GdipCreatePathIter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "path"]),
        #
        'GdipDeletePathIter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator"]),
        #
        'GdipPathIterNextSubpath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "startIndex", "endIndex", "isClosed"]),
        #
        'GdipPathIterNextSubpathPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "path", "isClosed"]),
        #
        'GdipPathIterNextPathType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "pathType", "startIndex", "endIndex"]),
        #
        'GdipPathIterNextMarker': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "startIndex", "endIndex"]),
        #
        'GdipPathIterNextMarkerPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "path"]),
        #
        'GdipPathIterGetCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "count"]),
        #
        'GdipPathIterGetSubpathCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "count"]),
        #
        'GdipPathIterIsValid': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "valid"]),
        #
        'GdipPathIterHasCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "hasCurve"]),
        #
        'GdipPathIterRewind': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["iterator"]),
        #
        'GdipPathIterEnumerate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "points", "types", "count"]),
        #
        'GdipPathIterCopyData': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["iterator", "resultCount", "points", "types", "startIndex", "endIndex"]),
        #
        'GdipCreateMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix"]),
        #
        'GdipCreateMatrix2': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["m11", "m12", "m21", "m22", "dx", "dy", "matrix"]),
        #
        'GdipCreateMatrix3': SimTypeFunction([SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "dstplg", "matrix"]),
        #
        'GdipCreateMatrix3I': SimTypeFunction([SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "dstplg", "matrix"]),
        #
        'GdipCloneMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "cloneMatrix"]),
        #
        'GdipDeleteMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix"]),
        #
        'GdipSetMatrixElements': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "m11", "m12", "m21", "m22", "dx", "dy"]),
        #
        'GdipMultiplyMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "matrix2", "order"]),
        #
        'GdipTranslateMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "offsetX", "offsetY", "order"]),
        #
        'GdipScaleMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "scaleX", "scaleY", "order"]),
        #
        'GdipRotateMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "angle", "order"]),
        #
        'GdipShearMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "shearX", "shearY", "order"]),
        #
        'GdipInvertMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix"]),
        #
        'GdipTransformMatrixPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "pts", "count"]),
        #
        'GdipTransformMatrixPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "pts", "count"]),
        #
        'GdipVectorTransformMatrixPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "pts", "count"]),
        #
        'GdipVectorTransformMatrixPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "pts", "count"]),
        #
        'GdipGetMatrixElements': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "matrixOut"]),
        #
        'GdipIsMatrixInvertible': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "result"]),
        #
        'GdipIsMatrixIdentity': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "result"]),
        #
        'GdipIsMatrixEqual': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["matrix", "matrix2", "result"]),
        #
        'GdipCreateRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region"]),
        #
        'GdipCreateRegionRect': SimTypeFunction([SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "region"]),
        #
        'GdipCreateRegionRectI': SimTypeFunction([SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "region"]),
        #
        'GdipCreateRegionPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "region"]),
        #
        'GdipCreateRegionRgnData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["regionData", "size", "region"]),
        #
        'GdipCreateRegionHrgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hRgn", "region"]),
        #
        'GdipCloneRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "cloneRegion"]),
        #
        'GdipDeleteRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region"]),
        #
        'GdipSetInfinite': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region"]),
        #
        'GdipSetEmpty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region"]),
        #
        'GdipCombineRegionRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["region", "rect", "combineMode"]),
        #
        'GdipCombineRegionRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["region", "rect", "combineMode"]),
        #
        'GdipCombineRegionPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["region", "path", "combineMode"]),
        #
        'GdipCombineRegionRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["region", "region2", "combineMode"]),
        #
        'GdipTranslateRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "dx", "dy"]),
        #
        'GdipTranslateRegionI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["region", "dx", "dy"]),
        #
        'GdipTransformRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "matrix"]),
        #
        'GdipGetRegionBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "graphics", "rect"]),
        #
        'GdipGetRegionBoundsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "graphics", "rect"]),
        #
        'GdipGetRegionHRgn': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "graphics", "hRgn"]),
        #
        'GdipIsEmptyRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "graphics", "result"]),
        #
        'GdipIsInfiniteRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "graphics", "result"]),
        #
        'GdipIsEqualRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "region2", "graphics", "result"]),
        #
        'GdipGetRegionDataSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "bufferSize"]),
        #
        'GdipGetRegionData': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "buffer", "bufferSize", "sizeFilled"]),
        #
        'GdipIsVisibleRegionPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "x", "y", "graphics", "result"]),
        #
        'GdipIsVisibleRegionPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "x", "y", "graphics", "result"]),
        #
        'GdipIsVisibleRegionRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "x", "y", "width", "height", "graphics", "result"]),
        #
        'GdipIsVisibleRegionRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "x", "y", "width", "height", "graphics", "result"]),
        #
        'GdipGetRegionScansCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "count", "matrix"]),
        #
        'GdipGetRegionScans': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "rects", "count", "matrix"]),
        #
        'GdipGetRegionScansI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["region", "rects", "count", "matrix"]),
        #
        'GdipCloneBrush': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "cloneBrush"]),
        #
        'GdipDeleteBrush': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush"]),
        #
        'GdipGetBrushType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="BrushType"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "type"]),
        #
        'GdipCreateHatchBrush': SimTypeFunction([SimTypeInt(signed=False, label="HatchStyle"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hatchstyle", "forecol", "backcol", "brush"]),
        #
        'GdipGetHatchStyle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="HatchStyle"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "hatchstyle"]),
        #
        'GdipGetHatchForegroundColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "forecol"]),
        #
        'GdipGetHatchBackgroundColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "backcol"]),
        #
        'GdipCreateTexture': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "wrapmode", "texture"]),
        #
        'GdipCreateTexture2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "wrapmode", "x", "y", "width", "height", "texture"]),
        #
        'GdipCreateTextureIA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "imageAttributes", "x", "y", "width", "height", "texture"]),
        #
        'GdipCreateTexture2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "wrapmode", "x", "y", "width", "height", "texture"]),
        #
        'GdipCreateTextureIAI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "imageAttributes", "x", "y", "width", "height", "texture"]),
        #
        'GdipGetTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipSetTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipResetTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush"]),
        #
        'GdipMultiplyTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix", "order"]),
        #
        'GdipTranslateTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "dx", "dy", "order"]),
        #
        'GdipScaleTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "sx", "sy", "order"]),
        #
        'GdipRotateTextureTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "angle", "order"]),
        #
        'GdipSetTextureWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipGetTextureWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WrapMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipGetTextureImage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "image"]),
        #
        'GdipCreateSolidFill': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["color", "brush"]),
        #
        'GdipSetSolidFillColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "color"]),
        #
        'GdipGetSolidFillColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "color"]),
        #
        'GdipCreateLineBrush': SimTypeFunction([SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["point1", "point2", "color1", "color2", "wrapMode", "lineGradient"]),
        #
        'GdipCreateLineBrushI': SimTypeFunction([SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["point1", "point2", "color1", "color2", "wrapMode", "lineGradient"]),
        #
        'GdipCreateLineBrushFromRect': SimTypeFunction([SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LinearGradientMode"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "color1", "color2", "mode", "wrapMode", "lineGradient"]),
        #
        'GdipCreateLineBrushFromRectI': SimTypeFunction([SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LinearGradientMode"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "color1", "color2", "mode", "wrapMode", "lineGradient"]),
        #
        'GdipCreateLineBrushFromRectWithAngle': SimTypeFunction([SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "color1", "color2", "angle", "isAngleScalable", "wrapMode", "lineGradient"]),
        #
        'GdipCreateLineBrushFromRectWithAngleI': SimTypeFunction([SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["rect", "color1", "color2", "angle", "isAngleScalable", "wrapMode", "lineGradient"]),
        #
        'GdipSetLineColors': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "color1", "color2"]),
        #
        'GdipGetLineColors': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "colors"]),
        #
        'GdipGetLineRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "rect"]),
        #
        'GdipGetLineRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "rect"]),
        #
        'GdipSetLineGammaCorrection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "useGammaCorrection"]),
        #
        'GdipGetLineGammaCorrection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "useGammaCorrection"]),
        #
        'GdipGetLineBlendCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipGetLineBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetLineBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipGetLinePresetBlendCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipGetLinePresetBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetLinePresetBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetLineSigmaBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "focus", "scale"]),
        #
        'GdipSetLineLinearBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "focus", "scale"]),
        #
        'GdipSetLineWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipGetLineWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WrapMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipGetLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipSetLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipResetLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush"]),
        #
        'GdipMultiplyLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix", "order"]),
        #
        'GdipTranslateLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "dx", "dy", "order"]),
        #
        'GdipScaleLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "sx", "sy", "order"]),
        #
        'GdipRotateLineTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "angle", "order"]),
        #
        'GdipCreatePathGradient': SimTypeFunction([SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["points", "count", "wrapMode", "polyGradient"]),
        #
        'GdipCreatePathGradientI': SimTypeFunction([SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WrapMode"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["points", "count", "wrapMode", "polyGradient"]),
        #
        'GdipCreatePathGradientFromPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["path", "polyGradient"]),
        #
        'GdipGetPathGradientCenterColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "colors"]),
        #
        'GdipSetPathGradientCenterColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "colors"]),
        #
        'GdipGetPathGradientSurroundColorsWithCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "color", "count"]),
        #
        'GdipSetPathGradientSurroundColorsWithCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "color", "count"]),
        #
        'GdipGetPathGradientPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "path"]),
        #
        'GdipSetPathGradientPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "path"]),
        #
        'GdipGetPathGradientCenterPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "points"]),
        #
        'GdipGetPathGradientCenterPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "points"]),
        #
        'GdipSetPathGradientCenterPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "points"]),
        #
        'GdipSetPathGradientCenterPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "points"]),
        #
        'GdipGetPathGradientRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "rect"]),
        #
        'GdipGetPathGradientRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "rect"]),
        #
        'GdipGetPathGradientPointCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipGetPathGradientSurroundColorCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipSetPathGradientGammaCorrection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "useGammaCorrection"]),
        #
        'GdipGetPathGradientGammaCorrection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "useGammaCorrection"]),
        #
        'GdipGetPathGradientBlendCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipGetPathGradientBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetPathGradientBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipGetPathGradientPresetBlendCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "count"]),
        #
        'GdipGetPathGradientPresetBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetPathGradientPresetBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "blend", "positions", "count"]),
        #
        'GdipSetPathGradientSigmaBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "focus", "scale"]),
        #
        'GdipSetPathGradientLinearBlend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "focus", "scale"]),
        #
        'GdipGetPathGradientWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WrapMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipSetPathGradientWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "wrapmode"]),
        #
        'GdipGetPathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipSetPathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix"]),
        #
        'GdipResetPathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush"]),
        #
        'GdipMultiplyPathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "matrix", "order"]),
        #
        'GdipTranslatePathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "dx", "dy", "order"]),
        #
        'GdipScalePathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "sx", "sy", "order"]),
        #
        'GdipRotatePathGradientTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "angle", "order"]),
        #
        'GdipGetPathGradientFocusScales': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "xScale", "yScale"]),
        #
        'GdipSetPathGradientFocusScales': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "xScale", "yScale"]),
        #
        'GdipCreatePen1': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeFloat(size=32), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["color", "width", "unit", "pen"]),
        #
        'GdipCreatePen2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["brush", "width", "unit", "pen"]),
        #
        'GdipClonePen': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "clonepen"]),
        #
        'GdipDeletePen': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen"]),
        #
        'GdipSetPenWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "width"]),
        #
        'GdipGetPenWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "width"]),
        #
        'GdipSetPenUnit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="Unit")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "unit"]),
        #
        'GdipGetPenUnit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="Unit"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "unit"]),
        #
        'GdipSetPenLineCap197819': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap"), SimTypeInt(signed=False, label="LineCap"), SimTypeInt(signed=False, label="DashCap")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "startCap", "endCap", "dashCap"]),
        #
        'GdipSetPenStartCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "startCap"]),
        #
        'GdipSetPenEndCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "endCap"]),
        #
        'GdipSetPenDashCap197819': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="DashCap")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dashCap"]),
        #
        'GdipGetPenStartCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineCap"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "startCap"]),
        #
        'GdipGetPenEndCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineCap"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "endCap"]),
        #
        'GdipGetPenDashCap197819': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DashCap"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dashCap"]),
        #
        'GdipSetPenLineJoin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineJoin")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "lineJoin"]),
        #
        'GdipGetPenLineJoin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineJoin"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "lineJoin"]),
        #
        'GdipSetPenCustomStartCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "customCap"]),
        #
        'GdipGetPenCustomStartCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "customCap"]),
        #
        'GdipSetPenCustomEndCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "customCap"]),
        #
        'GdipGetPenCustomEndCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "customCap"]),
        #
        'GdipSetPenMiterLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "miterLimit"]),
        #
        'GdipGetPenMiterLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "miterLimit"]),
        #
        'GdipSetPenMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="PenAlignment")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "penMode"]),
        #
        'GdipGetPenMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PenAlignment"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "penMode"]),
        #
        'GdipSetPenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "matrix"]),
        #
        'GdipGetPenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "matrix"]),
        #
        'GdipResetPenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen"]),
        #
        'GdipMultiplyPenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "matrix", "order"]),
        #
        'GdipTranslatePenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dx", "dy", "order"]),
        #
        'GdipScalePenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "sx", "sy", "order"]),
        #
        'GdipRotatePenTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "angle", "order"]),
        #
        'GdipSetPenColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "argb"]),
        #
        'GdipGetPenColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "argb"]),
        #
        'GdipSetPenBrushFill': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "brush"]),
        #
        'GdipGetPenBrushFill': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "brush"]),
        #
        'GdipGetPenFillType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PenType"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "type"]),
        #
        'GdipGetPenDashStyle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DashStyle"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dashstyle"]),
        #
        'GdipSetPenDashStyle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="DashStyle")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dashstyle"]),
        #
        'GdipGetPenDashOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "offset"]),
        #
        'GdipSetPenDashOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "offset"]),
        #
        'GdipGetPenDashCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "count"]),
        #
        'GdipSetPenDashArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dash", "count"]),
        #
        'GdipGetPenDashArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dash", "count"]),
        #
        'GdipGetPenCompoundCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "count"]),
        #
        'GdipSetPenCompoundArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dash", "count"]),
        #
        'GdipGetPenCompoundArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["pen", "dash", "count"]),
        #
        'GdipCreateCustomLineCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap"), SimTypeFloat(size=32), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fillPath", "strokePath", "baseCap", "baseInset", "customCap"]),
        #
        'GdipDeleteCustomLineCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap"]),
        #
        'GdipCloneCustomLineCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "clonedCap"]),
        #
        'GdipGetCustomLineCapType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CustomLineCapType"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "capType"]),
        #
        'GdipSetCustomLineCapStrokeCaps': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap"), SimTypeInt(signed=False, label="LineCap")], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "startCap", "endCap"]),
        #
        'GdipGetCustomLineCapStrokeCaps': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineCap"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineCap"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "startCap", "endCap"]),
        #
        'GdipSetCustomLineCapStrokeJoin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineJoin")], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "lineJoin"]),
        #
        'GdipGetCustomLineCapStrokeJoin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineJoin"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "lineJoin"]),
        #
        'GdipSetCustomLineCapBaseCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="LineCap")], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "baseCap"]),
        #
        'GdipGetCustomLineCapBaseCap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LineCap"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "baseCap"]),
        #
        'GdipSetCustomLineCapBaseInset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "inset"]),
        #
        'GdipGetCustomLineCapBaseInset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "inset"]),
        #
        'GdipSetCustomLineCapWidthScale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "widthScale"]),
        #
        'GdipGetCustomLineCapWidthScale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["customCap", "widthScale"]),
        #
        'GdipCreateAdjustableArrowCap': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["height", "width", "isFilled", "cap"]),
        #
        'GdipSetAdjustableArrowCapHeight': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "height"]),
        #
        'GdipGetAdjustableArrowCapHeight': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "height"]),
        #
        'GdipSetAdjustableArrowCapWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "width"]),
        #
        'GdipGetAdjustableArrowCapWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "width"]),
        #
        'GdipSetAdjustableArrowCapMiddleInset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "middleInset"]),
        #
        'GdipGetAdjustableArrowCapMiddleInset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "middleInset"]),
        #
        'GdipSetAdjustableArrowCapFillState': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "fillState"]),
        #
        'GdipGetAdjustableArrowCapFillState': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["cap", "fillState"]),
        #
        'GdipLoadImageFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "image"]),
        #
        'GdipLoadImageFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "image"]),
        #
        'GdipLoadImageFromStreamICM': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "image"]),
        #
        'GdipLoadImageFromFileICM': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "image"]),
        #
        'GdipCloneImage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "cloneImage"]),
        #
        'GdipDisposeImage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image"]),
        #
        'GdipSaveImageToFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("EncoderParameters", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "filename", "clsidEncoder", "encoderParams"]),
        #
        'GdipSaveImageToStream': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("EncoderParameters", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "stream", "clsidEncoder", "encoderParams"]),
        #
        'GdipSaveAdd': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("EncoderParameters", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "encoderParams"]),
        #
        'GdipSaveAddImage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("EncoderParameters", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "newImage", "encoderParams"]),
        #
        'GdipGetImageGraphicsContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "graphics"]),
        #
        'GdipGetImageBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="Unit"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "srcRect", "srcUnit"]),
        #
        'GdipGetImageDimension': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "width", "height"]),
        #
        'GdipGetImageType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="ImageType"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "type"]),
        #
        'GdipGetImageWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "width"]),
        #
        'GdipGetImageHeight': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "height"]),
        #
        'GdipGetImageHorizontalResolution': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "resolution"]),
        #
        'GdipGetImageVerticalResolution': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "resolution"]),
        #
        'GdipGetImageFlags': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "flags"]),
        #
        'GdipGetImageRawFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "format"]),
        #
        'GdipGetImagePixelFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "format"]),
        #
        'GdipGetImageThumbnail': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "thumbWidth", "thumbHeight", "thumbImage", "callback", "callbackData"]),
        #
        'GdipGetEncoderParameterListSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "clsidEncoder", "size"]),
        #
        'GdipGetEncoderParameterList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EncoderParameters", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "clsidEncoder", "size", "buffer"]),
        #
        'GdipImageGetFrameDimensionsCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "count"]),
        #
        'GdipImageGetFrameDimensionsList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["image", "dimensionIDs", "count"]),
        #
        'GdipImageGetFrameCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "dimensionID", "count"]),
        #
        'GdipImageSelectActiveFrame': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["image", "dimensionID", "frameIndex"]),
        #
        'GdipImageRotateFlip': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="RotateFlipType")], SimTypeInt(signed=False, label="Status"), arg_names=["image", "rfType"]),
        #
        'GdipGetImagePalette': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ColorPalette", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["image", "palette", "size"]),
        #
        'GdipSetImagePalette': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ColorPalette", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "palette"]),
        #
        'GdipGetImagePaletteSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "size"]),
        #
        'GdipGetPropertyCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "numOfProperty"]),
        #
        'GdipGetPropertyIdList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "numOfProperty", "list"]),
        #
        'GdipGetPropertyItemSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "propId", "size"]),
        #
        'GdipGetPropertyItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PropertyItem", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "propId", "propSize", "buffer"]),
        #
        'GdipGetPropertySize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "totalBufferSize", "numProperties"]),
        #
        'GdipGetAllPropertyItems': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PropertyItem", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "totalBufferSize", "numProperties", "allItems"]),
        #
        'GdipRemovePropertyItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["image", "propId"]),
        #
        'GdipSetPropertyItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PropertyItem", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "item"]),
        #
        'GdipFindFirstImageItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ImageItemData", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "item"]),
        #
        'GdipFindNextImageItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ImageItemData", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "item"]),
        #
        'GdipGetImageItemData': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ImageItemData", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image", "item"]),
        #
        'GdipImageForceValidation': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["image"]),
        #
        'GdipCreateBitmapFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "bitmap"]),
        #
        'GdipCreateBitmapFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "bitmap"]),
        #
        'GdipCreateBitmapFromStreamICM': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "bitmap"]),
        #
        'GdipCreateBitmapFromFileICM': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "bitmap"]),
        #
        'GdipCreateBitmapFromScan0': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["width", "height", "stride", "format", "scan0", "bitmap"]),
        #
        'GdipCreateBitmapFromGraphics': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["width", "height", "target", "bitmap"]),
        #
        'GdipCreateBitmapFromDirectDrawSurface': SimTypeFunction([SimTypeBottom(label="IDirectDrawSurface7"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["surface", "bitmap"]),
        #
        'GdipCreateBitmapFromGdiDib': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["gdiBitmapInfo", "gdiBitmapData", "bitmap"]),
        #
        'GdipCreateBitmapFromHBITMAP': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hbm", "hpal", "bitmap"]),
        #
        'GdipCreateHBITMAPFromBitmap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "hbmReturn", "background"]),
        #
        'GdipCreateBitmapFromHICON': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hicon", "bitmap"]),
        #
        'GdipCreateHICONFromBitmap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "hbmReturn"]),
        #
        'GdipCreateBitmapFromResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hInstance", "lpBitmapName", "bitmap"]),
        #
        'GdipCloneBitmapArea': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["x", "y", "width", "height", "format", "srcBitmap", "dstBitmap"]),
        #
        'GdipCloneBitmapAreaI': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["x", "y", "width", "height", "format", "srcBitmap", "dstBitmap"]),
        #
        'GdipBitmapLockBits': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("BitmapData", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "rect", "flags", "format", "lockedBitmapData"]),
        #
        'GdipBitmapUnlockBits': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("BitmapData", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "lockedBitmapData"]),
        #
        'GdipBitmapGetPixel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "x", "y", "color"]),
        #
        'GdipBitmapSetPixel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "x", "y", "color"]),
        #
        'GdipImageSetAbort': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeBottom(label="GdiplusAbort")], SimTypeInt(signed=False, label="Status"), arg_names=["pImage", "pIAbort"]),
        #
        'GdipGraphicsSetAbort': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeBottom(label="GdiplusAbort")], SimTypeInt(signed=False, label="Status"), arg_names=["pGraphics", "pIAbort"]),
        #
        'GdipBitmapConvertFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DitherType"), SimTypeInt(signed=False, label="PaletteType"), SimTypePointer(SimTypeRef("ColorPalette", SimStruct), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["pInputBitmap", "format", "dithertype", "palettetype", "palette", "alphaThresholdPercent"]),
        #
        'GdipInitializePalette': SimTypeFunction([SimTypePointer(SimTypeRef("ColorPalette", SimStruct), offset=0), SimTypeInt(signed=False, label="PaletteType"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["palette", "palettetype", "optimalColors", "useTransparentColor", "bitmap"]),
        #
        'GdipBitmapApplyEffect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "effect", "roi", "useAuxData", "auxData", "auxDataSize"]),
        #
        'GdipBitmapCreateApplyEffect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["inputBitmaps", "numInputs", "effect", "roi", "outputRect", "outputBitmap", "useAuxData", "auxData", "auxDataSize"]),
        #
        'GdipBitmapGetHistogram': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="HistogramFormat"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "format", "NumberOfEntries", "channel0", "channel1", "channel2", "channel3"]),
        #
        'GdipBitmapGetHistogramSize': SimTypeFunction([SimTypeInt(signed=False, label="HistogramFormat"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "NumberOfEntries"]),
        #
        'GdipBitmapSetResolution': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "xdpi", "ydpi"]),
        #
        'GdipCreateImageAttributes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr"]),
        #
        'GdipCloneImageAttributes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "cloneImageattr"]),
        #
        'GdipDisposeImageAttributes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr"]),
        #
        'GdipSetImageAttributesToIdentity': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type"]),
        #
        'GdipResetImageAttributes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type"]),
        #
        'GdipSetImageAttributesColorMatrix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("ColorMatrix", SimStruct), offset=0), SimTypePointer(SimTypeRef("ColorMatrix", SimStruct), offset=0), SimTypeInt(signed=False, label="ColorMatrixFlags")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "colorMatrix", "grayMatrix", "flags"]),
        #
        'GdipSetImageAttributesThreshold': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "threshold"]),
        #
        'GdipSetImageAttributesGamma': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "gamma"]),
        #
        'GdipSetImageAttributesNoOp': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag"]),
        #
        'GdipSetImageAttributesColorKeys': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "colorLow", "colorHigh"]),
        #
        'GdipSetImageAttributesOutputChannel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="ColorChannelFlags")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "channelFlags"]),
        #
        'GdipSetImageAttributesOutputChannelColorProfile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "colorProfileFilename"]),
        #
        'GdipSetImageAttributesRemapTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ColorAdjustType"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ColorMap", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "type", "enableFlag", "mapSize", "map"]),
        #
        'GdipSetImageAttributesWrapMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="WrapMode"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["imageAttr", "wrap", "argb", "clamp"]),
        #
        'GdipGetImageAttributesAdjustedPalette': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("ColorPalette", SimStruct), offset=0), SimTypeInt(signed=False, label="ColorAdjustType")], SimTypeInt(signed=False, label="Status"), arg_names=["imageAttr", "colorPalette", "colorAdjustType"]),
        #
        'GdipFlush': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="FlushIntention")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "intention"]),
        #
        'GdipCreateFromHDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hdc", "graphics"]),
        #
        'GdipCreateFromHDC2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hdc", "hDevice", "graphics"]),
        #
        'GdipCreateFromHWND': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hwnd", "graphics"]),
        #
        'GdipCreateFromHWNDICM': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hwnd", "graphics"]),
        #
        'GdipDeleteGraphics': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics"]),
        #
        'GdipGetDC': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "hdc"]),
        #
        'GdipReleaseDC': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "hdc"]),
        #
        'GdipSetCompositingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CompositingMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "compositingMode"]),
        #
        'GdipGetCompositingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CompositingMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "compositingMode"]),
        #
        'GdipSetRenderingOrigin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y"]),
        #
        'GdipGetRenderingOrigin': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y"]),
        #
        'GdipSetCompositingQuality': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CompositingQuality")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "compositingQuality"]),
        #
        'GdipGetCompositingQuality': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CompositingQuality"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "compositingQuality"]),
        #
        'GdipSetSmoothingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="SmoothingMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "smoothingMode"]),
        #
        'GdipGetSmoothingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SmoothingMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "smoothingMode"]),
        #
        'GdipSetPixelOffsetMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="PixelOffsetMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pixelOffsetMode"]),
        #
        'GdipGetPixelOffsetMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PixelOffsetMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pixelOffsetMode"]),
        #
        'GdipSetTextRenderingHint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="TextRenderingHint")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "mode"]),
        #
        'GdipGetTextRenderingHint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="TextRenderingHint"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "mode"]),
        #
        'GdipSetTextContrast': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "contrast"]),
        #
        'GdipGetTextContrast': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "contrast"]),
        #
        'GdipSetInterpolationMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="InterpolationMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "interpolationMode"]),
        #
        'GdipGetInterpolationMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="InterpolationMode"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "interpolationMode"]),
        #
        'GdipSetWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "matrix"]),
        #
        'GdipResetWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics"]),
        #
        'GdipMultiplyWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "matrix", "order"]),
        #
        'GdipTranslateWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dx", "dy", "order"]),
        #
        'GdipScaleWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "sx", "sy", "order"]),
        #
        'GdipRotateWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=False, label="MatrixOrder")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "angle", "order"]),
        #
        'GdipGetWorldTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "matrix"]),
        #
        'GdipResetPageTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics"]),
        #
        'GdipGetPageUnit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="Unit"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "unit"]),
        #
        'GdipGetPageScale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "scale"]),
        #
        'GdipSetPageUnit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="Unit")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "unit"]),
        #
        'GdipSetPageScale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "scale"]),
        #
        'GdipGetDpiX': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dpi"]),
        #
        'GdipGetDpiY': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dpi"]),
        #
        'GdipTransformPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CoordinateSpace"), SimTypeInt(signed=False, label="CoordinateSpace"), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "destSpace", "srcSpace", "points", "count"]),
        #
        'GdipTransformPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CoordinateSpace"), SimTypeInt(signed=False, label="CoordinateSpace"), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "destSpace", "srcSpace", "points", "count"]),
        #
        'GdipGetNearestColor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "argb"]),
        #
        'GdipCreateHalftonePalette': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GdipDrawLine': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x1", "y1", "x2", "y2"]),
        #
        'GdipDrawLineI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x1", "y1", "x2", "y2"]),
        #
        'GdipDrawLines': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawLinesI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawArc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipDrawArcI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipDrawBezier': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'GdipDrawBezierI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x1", "y1", "x2", "y2", "x3", "y3", "x4", "y4"]),
        #
        'GdipDrawBeziers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawBeziersI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawRectangle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height"]),
        #
        'GdipDrawRectangleI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height"]),
        #
        'GdipDrawRectangles': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "rects", "count"]),
        #
        'GdipDrawRectanglesI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "rects", "count"]),
        #
        'GdipDrawEllipse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height"]),
        #
        'GdipDrawEllipseI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height"]),
        #
        'GdipDrawPie': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipDrawPieI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipDrawPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawPolygonI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "path"]),
        #
        'GdipDrawCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawCurveI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawCurve2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "tension"]),
        #
        'GdipDrawCurve2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "tension"]),
        #
        'GdipDrawCurve3': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "offset", "numberOfSegments", "tension"]),
        #
        'GdipDrawCurve3I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "offset", "numberOfSegments", "tension"]),
        #
        'GdipDrawClosedCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawClosedCurveI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count"]),
        #
        'GdipDrawClosedCurve2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "tension"]),
        #
        'GdipDrawClosedCurve2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "pen", "points", "count", "tension"]),
        #
        'GdipGraphicsClear': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "color"]),
        #
        'GdipFillRectangle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height"]),
        #
        'GdipFillRectangleI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height"]),
        #
        'GdipFillRectangles': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "rects", "count"]),
        #
        'GdipFillRectanglesI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "rects", "count"]),
        #
        'GdipFillPolygon': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FillMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count", "fillMode"]),
        #
        'GdipFillPolygonI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FillMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count", "fillMode"]),
        #
        'GdipFillPolygon2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count"]),
        #
        'GdipFillPolygon2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count"]),
        #
        'GdipFillEllipse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height"]),
        #
        'GdipFillEllipseI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height"]),
        #
        'GdipFillPie': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipFillPieI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "x", "y", "width", "height", "startAngle", "sweepAngle"]),
        #
        'GdipFillPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "path"]),
        #
        'GdipFillClosedCurve': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count"]),
        #
        'GdipFillClosedCurveI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count"]),
        #
        'GdipFillClosedCurve2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeInt(signed=False, label="FillMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count", "tension", "fillMode"]),
        #
        'GdipFillClosedCurve2I': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeInt(signed=False, label="FillMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "points", "count", "tension", "fillMode"]),
        #
        'GdipFillRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "brush", "region"]),
        #
        'GdipDrawImageFX': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="Unit")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "source", "xForm", "effect", "imageAttributes", "srcUnit"]),
        #
        'GdipDrawImage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y"]),
        #
        'GdipDrawImageI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y"]),
        #
        'GdipDrawImageRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y", "width", "height"]),
        #
        'GdipDrawImageRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y", "width", "height"]),
        #
        'GdipDrawImagePoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "dstpoints", "count"]),
        #
        'GdipDrawImagePointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "dstpoints", "count"]),
        #
        'GdipDrawImagePointRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="Unit")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit"]),
        #
        'GdipDrawImagePointRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="Unit")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "x", "y", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit"]),
        #
        'GdipDrawImageRectRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "dstx", "dsty", "dstwidth", "dstheight", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit", "imageAttributes", "callback", "callbackData"]),
        #
        'GdipDrawImageRectRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "dstx", "dsty", "dstwidth", "dstheight", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit", "imageAttributes", "callback", "callbackData"]),
        #
        'GdipDrawImagePointsRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "points", "count", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit", "imageAttributes", "callback", "callbackData"]),
        #
        'GdipDrawImagePointsRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "image", "points", "count", "srcx", "srcy", "srcwidth", "srcheight", "srcUnit", "imageAttributes", "callback", "callbackData"]),
        #
        'GdipEnumerateMetafileDestPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoint", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileDestPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoint", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileDestRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destRect", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileDestRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destRect", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileDestPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoints", "count", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileDestPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoints", "count", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestPoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoint", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestPointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoint", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destRect", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destRect", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestPoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoints", "count", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipEnumerateMetafileSrcRectDestPointsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Point", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "metafile", "destPoints", "count", "srcRect", "srcUnit", "callback", "callbackData", "imageAttributes"]),
        #
        'GdipPlayMetafileRecord': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="EmfPlusRecordType"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["metafile", "recordType", "flags", "dataSize", "data"]),
        #
        'GdipSetClipGraphics': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "srcgraphics", "combineMode"]),
        #
        'GdipSetClipRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "width", "height", "combineMode"]),
        #
        'GdipSetClipRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "width", "height", "combineMode"]),
        #
        'GdipSetClipPath': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "path", "combineMode"]),
        #
        'GdipSetClipRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "region", "combineMode"]),
        #
        'GdipSetClipHrgn': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CombineMode")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "hRgn", "combineMode"]),
        #
        'GdipResetClip': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics"]),
        #
        'GdipTranslateClip': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dx", "dy"]),
        #
        'GdipTranslateClipI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dx", "dy"]),
        #
        'GdipGetClip': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "region"]),
        #
        'GdipGetClipBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "rect"]),
        #
        'GdipGetClipBoundsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "rect"]),
        #
        'GdipIsClipEmpty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "result"]),
        #
        'GdipGetVisibleClipBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "rect"]),
        #
        'GdipGetVisibleClipBoundsI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "rect"]),
        #
        'GdipIsVisibleClipEmpty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "result"]),
        #
        'GdipIsVisiblePoint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "result"]),
        #
        'GdipIsVisiblePointI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "result"]),
        #
        'GdipIsVisibleRect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "width", "height", "result"]),
        #
        'GdipIsVisibleRectI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "x", "y", "width", "height", "result"]),
        #
        'GdipSaveGraphics': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "state"]),
        #
        'GdipRestoreGraphics': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "state"]),
        #
        'GdipBeginContainer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dstrect", "srcrect", "unit", "state"]),
        #
        'GdipBeginContainerI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "dstrect", "srcrect", "unit", "state"]),
        #
        'GdipBeginContainer2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "state"]),
        #
        'GdipEndContainer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "state"]),
        #
        'GdipGetMetafileHeaderFromWmf': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WmfPlaceableFileHeader", SimStruct), offset=0), SimTypePointer(SimTypeRef("MetafileHeader", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hWmf", "wmfPlaceableFileHeader", "header"]),
        #
        'GdipGetMetafileHeaderFromEmf': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MetafileHeader", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hEmf", "header"]),
        #
        'GdipGetMetafileHeaderFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MetafileHeader", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "header"]),
        #
        'GdipGetMetafileHeaderFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeRef("MetafileHeader", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "header"]),
        #
        'GdipGetMetafileHeaderFromMetafile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("MetafileHeader", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["metafile", "header"]),
        #
        'GdipGetHemfFromMetafile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["metafile", "hEmf"]),
        #
        'GdipCreateStreamOnFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["filename", "access", "stream"]),
        #
        'GdipCreateMetafileFromWmf': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WmfPlaceableFileHeader", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hWmf", "deleteWmf", "wmfPlaceableFileHeader", "metafile"]),
        #
        'GdipCreateMetafileFromEmf': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hEmf", "deleteEmf", "metafile"]),
        #
        'GdipCreateMetafileFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["file", "metafile"]),
        #
        'GdipCreateMetafileFromWmfFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WmfPlaceableFileHeader", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["file", "wmfPlaceableFileHeader", "metafile"]),
        #
        'GdipCreateMetafileFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "metafile"]),
        #
        'GdipRecordMetafile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipRecordMetafileI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipRecordMetafileFileName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fileName", "referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipRecordMetafileFileNameI': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fileName", "referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipRecordMetafileStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipRecordMetafileStreamI': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeRef("Rect", SimStruct), offset=0), SimTypeInt(signed=False, label="MetafileFrameUnit"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["stream", "referenceHdc", "type", "frameRect", "frameUnit", "description", "metafile"]),
        #
        'GdipSetMetafileDownLevelRasterizationLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="Status"), arg_names=["metafile", "metafileRasterizationLimitDpi"]),
        #
        'GdipGetMetafileDownLevelRasterizationLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["metafile", "metafileRasterizationLimitDpi"]),
        #
        'GdipGetImageDecodersSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["numDecoders", "size"]),
        #
        'GdipGetImageDecoders': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ImageCodecInfo", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["numDecoders", "size", "decoders"]),
        #
        'GdipGetImageEncodersSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["numEncoders", "size"]),
        #
        'GdipGetImageEncoders': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ImageCodecInfo", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["numEncoders", "size", "encoders"]),
        #
        'GdipComment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "sizeData", "data"]),
        #
        'GdipCreateFontFamilyFromName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["name", "fontCollection", "fontFamily"]),
        #
        'GdipDeleteFontFamily': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontFamily"]),
        #
        'GdipCloneFontFamily': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontFamily", "clonedFontFamily"]),
        #
        'GdipGetGenericFontFamilySansSerif': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["nativeFamily"]),
        #
        'GdipGetGenericFontFamilySerif': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["nativeFamily"]),
        #
        'GdipGetGenericFontFamilyMonospace': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["nativeFamily"]),
        #
        'GdipGetFamilyName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="Status"), arg_names=["family", "name", "language"]),
        #
        'GdipIsStyleAvailable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["family", "style", "IsStyleAvailable"]),
        #
        'GdipGetEmHeight': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["family", "style", "EmHeight"]),
        #
        'GdipGetCellAscent': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["family", "style", "CellAscent"]),
        #
        'GdipGetCellDescent': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["family", "style", "CellDescent"]),
        #
        'GdipGetLineSpacing': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["family", "style", "LineSpacing"]),
        #
        'GdipCreateFontFromDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hdc", "font"]),
        #
        'GdipCreateFontFromLogfontA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hdc", "logfont", "font"]),
        #
        'GdipCreateFontFromLogfontW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["hdc", "logfont", "font"]),
        #
        'GdipCreateFont': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="Unit"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontFamily", "emSize", "style", "unit", "font"]),
        #
        'GdipCloneFont': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "cloneFont"]),
        #
        'GdipDeleteFont': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font"]),
        #
        'GdipGetFamily': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "family"]),
        #
        'GdipGetFontStyle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "style"]),
        #
        'GdipGetFontSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "size"]),
        #
        'GdipGetFontUnit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="Unit"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "unit"]),
        #
        'GdipGetFontHeight': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "graphics", "height"]),
        #
        'GdipGetFontHeightGivenDPI': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "dpi", "height"]),
        #
        'GdipGetLogFontA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "graphics", "logfontA"]),
        #
        'GdipGetLogFontW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["font", "graphics", "logfontW"]),
        #
        'GdipNewInstalledFontCollection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection"]),
        #
        'GdipNewPrivateFontCollection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection"]),
        #
        'GdipDeletePrivateFontCollection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection"]),
        #
        'GdipGetFontCollectionFamilyCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection", "numFound"]),
        #
        'GdipGetFontCollectionFamilyList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection", "numSought", "gpfamilies", "numFound"]),
        #
        'GdipPrivateAddFontFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection", "filename"]),
        #
        'GdipPrivateAddMemoryFont': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["fontCollection", "memory", "length"]),
        #
        'GdipDrawString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "string", "length", "font", "layoutRect", "stringFormat", "brush"]),
        #
        'GdipMeasureString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "string", "length", "font", "layoutRect", "stringFormat", "boundingBox", "codepointsFitted", "linesFilled"]),
        #
        'GdipMeasureCharacterRanges': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "string", "length", "font", "layoutRect", "stringFormat", "regionCount", "regions"]),
        #
        'GdipDrawDriverString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "text", "length", "font", "brush", "positions", "flags", "matrix"]),
        #
        'GdipMeasureDriverString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PointF", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RectF", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "text", "length", "font", "positions", "flags", "matrix", "boundingBox"]),
        #
        'GdipCreateStringFormat': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["formatAttributes", "language", "format"]),
        #
        'GdipStringFormatGetGenericDefault': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format"]),
        #
        'GdipStringFormatGetGenericTypographic': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format"]),
        #
        'GdipDeleteStringFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format"]),
        #
        'GdipCloneStringFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "newFormat"]),
        #
        'GdipSetStringFormatFlags': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "flags"]),
        #
        'GdipGetStringFormatFlags': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "flags"]),
        #
        'GdipSetStringFormatAlign': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="StringAlignment")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "align"]),
        #
        'GdipGetStringFormatAlign': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="StringAlignment"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "align"]),
        #
        'GdipSetStringFormatLineAlign': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="StringAlignment")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "align"]),
        #
        'GdipGetStringFormatLineAlign': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="StringAlignment"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "align"]),
        #
        'GdipSetStringFormatTrimming': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="StringTrimming")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "trimming"]),
        #
        'GdipGetStringFormatTrimming': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="StringTrimming"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "trimming"]),
        #
        'GdipSetStringFormatHotkeyPrefix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "hotkeyPrefix"]),
        #
        'GdipGetStringFormatHotkeyPrefix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "hotkeyPrefix"]),
        #
        'GdipSetStringFormatTabStops': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "firstTabOffset", "count", "tabStops"]),
        #
        'GdipGetStringFormatTabStops': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "count", "firstTabOffset", "tabStops"]),
        #
        'GdipGetStringFormatTabStopCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "count"]),
        #
        'GdipSetStringFormatDigitSubstitution': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="StringDigitSubstitute")], SimTypeInt(signed=False, label="Status"), arg_names=["format", "language", "substitute"]),
        #
        'GdipGetStringFormatDigitSubstitution': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="StringDigitSubstitute"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "language", "substitute"]),
        #
        'GdipGetStringFormatMeasurableCharacterRangeCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "count"]),
        #
        'GdipSetStringFormatMeasurableCharacterRanges': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("CharacterRange", SimStruct), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["format", "rangeCount", "ranges"]),
        #
        'GdipCreateCachedBitmap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["bitmap", "graphics", "cachedBitmap"]),
        #
        'GdipDeleteCachedBitmap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["cachedBitmap"]),
        #
        'GdipDrawCachedBitmap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["graphics", "cachedBitmap", "x", "y"]),
        #
        'GdipEmfToWmfBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hemf", "cbData16", "pData16", "iMapMode", "eFlags"]),
        #
        'GdipSetImageAttributesCachedBackground': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="Status"), arg_names=["imageattr", "enableFlag"]),
        #
        'GdipTestControl': SimTypeFunction([SimTypeInt(signed=False, label="GpTestControlEnum"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["control", "param1"]),
        #
        'GdiplusNotificationHook': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["token"]),
        #
        'GdiplusNotificationUnhook': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["token"]),
        #
        'GdipConvertToEmfPlus': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["refGraphics", "metafile", "conversionFailureFlag", "emfType", "description", "out_metafile"]),
        #
        'GdipConvertToEmfPlusToFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["refGraphics", "metafile", "conversionFailureFlag", "filename", "emfType", "description", "out_metafile"]),
        #
        'GdipConvertToEmfPlusToStream': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="EmfType"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="Status"), arg_names=["refGraphics", "metafile", "conversionFailureFlag", "stream", "emfType", "description", "out_metafile"]),
    }

lib.set_prototypes(prototypes)
