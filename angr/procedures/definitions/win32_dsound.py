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
lib.set_library_names("dsound.dll")
prototypes = \
    {
        #
        'DirectSoundCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSound"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcGuidDevice", "ppDS", "pUnkOuter"]),
        #
        'DirectSoundEnumerateA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDSEnumCallback", "pContext"]),
        #
        'DirectSoundEnumerateW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDSEnumCallback", "pContext"]),
        #
        'DirectSoundCaptureCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSoundCapture"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcGuidDevice", "ppDSC", "pUnkOuter"]),
        #
        'DirectSoundCaptureEnumerateA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDSEnumCallback", "pContext"]),
        #
        'DirectSoundCaptureEnumerateW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDSEnumCallback", "pContext"]),
        #
        'DirectSoundCreate8': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSound8"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcGuidDevice", "ppDS8", "pUnkOuter"]),
        #
        'DirectSoundCaptureCreate8': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSoundCapture"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcGuidDevice", "ppDSC8", "pUnkOuter"]),
        #
        'DirectSoundFullDuplexCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwBufferBytes": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32"), "lpwfxFormat": SimTypePointer(SimTypeBottom(label="WAVEFORMATEX"), offset=0), "dwFXCount": SimTypeInt(signed=False, label="UInt32"), "lpDSCFXDesc": SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "guidDSCFXClass": SimTypeBottom(label="Guid"), "guidDSCFXInstance": SimTypeBottom(label="Guid"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32")}, name="DSCEFFECTDESC", pack=False, align=None), offset=0)}, name="DSCBUFFERDESC", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwBufferBytes": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32"), "lpwfxFormat": SimTypePointer(SimTypeBottom(label="WAVEFORMATEX"), offset=0), "guid3DAlgorithm": SimTypeBottom(label="Guid")}, name="DSBUFFERDESC", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IDirectSoundFullDuplex"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSoundCaptureBuffer8"), offset=0), SimTypePointer(SimTypeBottom(label="IDirectSoundBuffer8"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcGuidCaptureDevice", "pcGuidRenderDevice", "pcDSCBufferDesc", "pcDSBufferDesc", "hWnd", "dwLevel", "ppDSFD", "ppDSCBuffer8", "ppDSBuffer8", "pUnkOuter"]),
        #
        'GetDeviceID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGuidSrc", "pGuidDest"]),
    }

lib.set_prototypes(prototypes)
