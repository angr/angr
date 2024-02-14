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
lib.set_library_names("d2d1.dll")
prototypes = \
    {
        #
        'D2D1CreateFactory': SimTypeFunction([SimTypeInt(signed=False, label="D2D1_FACTORY_TYPE"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("D2D1_FACTORY_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["factoryType", "riid", "pFactoryOptions", "ppIFactory"]),
        #
        'D2D1MakeRotateMatrix': SimTypeFunction([SimTypeFloat(size=32), SimTypeRef("D2D_POINT_2F", SimStruct), SimTypePointer(SimTypeRef("D2D_MATRIX_3X2_F", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["angle", "center", "matrix"]),
        #
        'D2D1MakeSkewMatrix': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeRef("D2D_POINT_2F", SimStruct), SimTypePointer(SimTypeRef("D2D_MATRIX_3X2_F", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["angleX", "angleY", "center", "matrix"]),
        #
        'D2D1IsMatrixInvertible': SimTypeFunction([SimTypePointer(SimTypeRef("D2D_MATRIX_3X2_F", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["matrix"]),
        #
        'D2D1InvertMatrix': SimTypeFunction([SimTypePointer(SimTypeRef("D2D_MATRIX_3X2_F", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["matrix"]),
        #
        'D2D1CreateDevice': SimTypeFunction([SimTypeBottom(label="IDXGIDevice"), SimTypePointer(SimTypeRef("D2D1_CREATION_PROPERTIES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID2D1Device"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dxgiDevice", "creationProperties", "d2dDevice"]),
        #
        'D2D1CreateDeviceContext': SimTypeFunction([SimTypeBottom(label="IDXGISurface"), SimTypePointer(SimTypeRef("D2D1_CREATION_PROPERTIES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID2D1DeviceContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dxgiSurface", "creationProperties", "d2dDeviceContext"]),
        #
        'D2D1ConvertColorSpace': SimTypeFunction([SimTypeInt(signed=False, label="D2D1_COLOR_SPACE"), SimTypeInt(signed=False, label="D2D1_COLOR_SPACE"), SimTypePointer(SimTypeRef("D2D1_COLOR_F", SimStruct), offset=0)], SimTypeRef("D2D1_COLOR_F", SimStruct), arg_names=["sourceColorSpace", "destinationColorSpace", "color"]),
        #
        'D2D1SinCos': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeBottom(label="Void"), arg_names=["angle", "s", "c"]),
        #
        'D2D1Tan': SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), arg_names=["angle"]),
        #
        'D2D1Vec3Length': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), arg_names=["x", "y", "z"]),
        #
        'D2D1ComputeMaximumScaleFactor': SimTypeFunction([SimTypePointer(SimTypeRef("D2D_MATRIX_3X2_F", SimStruct), offset=0)], SimTypeFloat(size=32), arg_names=["matrix"]),
        #
        'D2D1GetGradientMeshInteriorPointsFromCoonsPatch': SimTypeFunction([SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0), SimTypePointer(SimTypeRef("D2D_POINT_2F", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pPoint0", "pPoint1", "pPoint2", "pPoint3", "pPoint4", "pPoint5", "pPoint6", "pPoint7", "pPoint8", "pPoint9", "pPoint10", "pPoint11", "pTensorPoint11", "pTensorPoint12", "pTensorPoint21", "pTensorPoint22"]),
    }

lib.set_prototypes(prototypes)
