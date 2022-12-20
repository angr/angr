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
lib.set_library_names("hrtfapo.dll")
prototypes = \
    {
        #
        'CreateHrtfApo': SimTypeFunction([SimTypePointer(SimStruct({"distanceDecay": SimTypePointer(SimStruct({"type": SimTypeInt(signed=False, label="HrtfDistanceDecayType"), "maxGain": SimTypeFloat(size=32), "minGain": SimTypeFloat(size=32), "unityGainDistance": SimTypeFloat(size=32), "cutoffDistance": SimTypeFloat(size=32)}, name="HrtfDistanceDecay", pack=False, align=None), offset=0), "directivity": SimTypePointer(SimStruct({"type": SimTypeInt(signed=False, label="HrtfDirectivityType"), "scaling": SimTypeFloat(size=32)}, name="HrtfDirectivity", pack=False, align=None), offset=0)}, name="HrtfApoInit", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="IXAPO"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["init", "xApo"]),
    }

lib.set_prototypes(prototypes)
