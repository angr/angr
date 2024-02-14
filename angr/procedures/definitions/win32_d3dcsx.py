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
lib.set_library_names("d3dcsx.dll")
prototypes = \
    {
        #
        'D3DX11CreateScan': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DX11Scan"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "MaxElementScanSize", "MaxScanCount", "ppScan"]),
        #
        'D3DX11CreateSegmentedScan': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DX11SegmentedScan"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "MaxElementScanSize", "ppScan"]),
        #
        'D3DX11CreateFFT': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypePointer(SimTypeRef("D3DX11_FFT_DESC", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "pDesc", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT1DReal': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT1DComplex': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT2DReal': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Y", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT2DComplex': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Y", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT3DReal': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Y", "Z", "Flags", "pBufferInfo", "ppFFT"]),
        #
        'D3DX11CreateFFT3DComplex': SimTypeFunction([SimTypeBottom(label="ID3D11DeviceContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3DX11_FFT_BUFFER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DX11FFT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceContext", "X", "Y", "Z", "Flags", "pBufferInfo", "ppFFT"]),
    }

lib.set_prototypes(prototypes)
