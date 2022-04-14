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
lib.set_library_names("evr.dll")
prototypes = \
    {
        # 
        'MFIsFormatYUV': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Format"]),
        # 
        'MFGetPlaneSize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "dwWidth", "dwHeight", "pdwPlaneSize"]),
        # 
        'MFCreateVideoPresenter': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOwner", "riidDevice", "riid", "ppVideoPresenter"]),
        # 
        'MFCreateVideoMixer': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOwner", "riidDevice", "riid", "ppv"]),
        # 
        'MFCreateVideoMixerAndPresenter': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMixerOwner", "pPresenterOwner", "riidMixer", "ppvVideoMixer", "riidPresenter", "ppvVideoPresenter"]),
        # 
        'MFCreateVideoSampleFromSurface': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFSample"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkSurface", "ppSample"]),
        # 
        'MFCreateVideoSampleAllocator': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppSampleAllocator"]),
    }

lib.set_prototypes(prototypes)
