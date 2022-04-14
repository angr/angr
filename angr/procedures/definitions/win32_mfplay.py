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
lib.set_library_names("mfplay.dll")
prototypes = \
    {
        # 
        'MFPCreateMediaPlayer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="MFP_CREATION_OPTIONS"), SimTypeBottom(label="IMFPMediaPlayerCallback"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IMFPMediaPlayer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszURL", "fStartPlayback", "creationOptions", "pCallback", "hWnd", "ppMediaPlayer"]),
    }

lib.set_prototypes(prototypes)
