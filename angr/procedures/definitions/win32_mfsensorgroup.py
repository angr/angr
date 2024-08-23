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
lib.set_library_names("mfsensorgroup.dll")
prototypes = \
    {
        #
        'MFCreateSensorGroup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFSensorGroup"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SensorGroupSymbolicLink", "ppSensorGroup"]),
        #
        'MFCreateSensorStream': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAttributes"), SimTypeBottom(label="IMFCollection"), SimTypePointer(SimTypeBottom(label="IMFSensorStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StreamId", "pAttributes", "pMediaTypeCollection", "ppStream"]),
        #
        'MFCreateSensorProfile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFSensorProfile"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProfileType", "ProfileIndex", "Constraints", "ppProfile"]),
        #
        'MFCreateSensorProfileCollection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFSensorProfileCollection"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSensorProfile"]),
        #
        'MFCreateSensorActivityMonitor': SimTypeFunction([SimTypeBottom(label="IMFSensorActivitiesReportCallback"), SimTypePointer(SimTypeBottom(label="IMFSensorActivityMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCallback", "ppActivityMonitor"]),
        #
        'MFCreateRelativePanelWatcher': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFRelativePanelWatcher"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["videoDeviceId", "displayMonitorDeviceId", "ppRelativePanelWatcher"]),
        #
        'MFCreateCameraOcclusionStateMonitor': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFCameraOcclusionStateReportCallback"), SimTypePointer(SimTypeBottom(label="IMFCameraOcclusionStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["symbolicLink", "callback", "occlusionStateMonitor"]),
        #
        'MFCreateCameraControlMonitor': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFCameraControlNotify"), SimTypePointer(SimTypeBottom(label="IMFCameraControlMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["symbolicLink", "callback", "ppCameraControlMonitor"]),
        #
        'MFCreateVirtualCamera': SimTypeFunction([SimTypeInt(signed=False, label="MFVirtualCameraType"), SimTypeInt(signed=False, label="MFVirtualCameraLifetime"), SimTypeInt(signed=False, label="MFVirtualCameraAccess"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFVirtualCamera"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["type", "lifetime", "access", "friendlyName", "sourceId", "categories", "categoryCount", "virtualCamera"]),
        #
        'MFIsVirtualCameraTypeSupported': SimTypeFunction([SimTypeInt(signed=False, label="MFVirtualCameraType"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["type", "supported"]),
    }

lib.set_prototypes(prototypes)
