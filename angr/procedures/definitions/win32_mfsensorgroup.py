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
    }

lib.set_prototypes(prototypes)
