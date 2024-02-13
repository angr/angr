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
lib.set_library_names("windows.media.mediacontrol.dll")
prototypes = \
    {
        #
        'CreateRenderAudioStateMonitor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["audioStateMonitor"]),
        #
        'CreateRenderAudioStateMonitorForCategory': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "audioStateMonitor"]),
        #
        'CreateRenderAudioStateMonitorForCategoryAndDeviceRole': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypeInt(signed=False, label="ERole"), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "role", "audioStateMonitor"]),
        #
        'CreateRenderAudioStateMonitorForCategoryAndDeviceId': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "deviceId", "audioStateMonitor"]),
        #
        'CreateCaptureAudioStateMonitor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["audioStateMonitor"]),
        #
        'CreateCaptureAudioStateMonitorForCategory': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "audioStateMonitor"]),
        #
        'CreateCaptureAudioStateMonitorForCategoryAndDeviceRole': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypeInt(signed=False, label="ERole"), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "role", "audioStateMonitor"]),
        #
        'CreateCaptureAudioStateMonitorForCategoryAndDeviceId': SimTypeFunction([SimTypeInt(signed=False, label="AUDIO_STREAM_CATEGORY"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IAudioStateMonitor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["category", "deviceId", "audioStateMonitor"]),
    }

lib.set_prototypes(prototypes)
