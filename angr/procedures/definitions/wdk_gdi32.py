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
lib.set_library_names("gdi32.dll")
prototypes = \
    {
        #
        'D3DKMTCreateAllocation': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEALLOCATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateAllocation2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEALLOCATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryResourceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYRESOURCEINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryResourceInfoFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTShareObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cObjects", "hObjects", "pObjectAttributes", "dwDesiredAccess", "phSharedNtHandle"]),
        #
        'D3DKMTOpenNtHandleFromName': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENNTHANDLEFROMNAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenResourceFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENRESOURCEFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenSyncObjectFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENSYNCOBJECTFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenResource': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENRESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenResource2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENRESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyAllocation': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYALLOCATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyAllocation2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYALLOCATION2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetAllocationPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETALLOCATIONPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryAllocationResidency': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYALLOCATIONRESIDENCY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateDevice': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEDEVICE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyDevice': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYDEVICE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateContext': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATECONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyContext': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYCONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateSynchronizationObject': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATESYNCHRONIZATIONOBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateSynchronizationObject2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATESYNCHRONIZATIONOBJECT2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenSynchronizationObject': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENSYNCHRONIZATIONOBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroySynchronizationObject': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYSYNCHRONIZATIONOBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForSynchronizationObject': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORSYNCHRONIZATIONOBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForSynchronizationObject2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORSYNCHRONIZATIONOBJECT2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSignalSynchronizationObject': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SIGNALSYNCHRONIZATIONOBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSignalSynchronizationObject2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SIGNALSYNCHRONIZATIONOBJECT2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTLock': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_LOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUnlock': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_UNLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetDisplayModeList': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETDISPLAYMODELIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetDisplayMode': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETDISPLAYMODE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetMultisampleMethodList': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETMULTISAMPLEMETHODLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPresent': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_PRESENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTRender': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_RENDER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetRuntimeData': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETRUNTIMEDATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryAdapterInfo': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYADAPTERINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenAdapterFromHdc': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENADAPTERFROMHDC", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenAdapterFromGdiDisplayName': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenAdapterFromDeviceName': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENADAPTERFROMDEVICENAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCloseAdapter': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CLOSEADAPTER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetSharedPrimaryHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETSHAREDPRIMARYHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTEscape': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ESCAPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYSTATISTICS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetVidPnSourceOwner': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETVIDPNSOURCEOWNER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetPresentHistory': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETPRESENTHISTORY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetPresentQueueEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAdapter", "param1"]),
        #
        'D3DKMTCreateOverlay': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEOVERLAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUpdateOverlay': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_UPDATEOVERLAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTFlipOverlay': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_FLIPOVERLAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyOverlay': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYOVERLAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForVerticalBlankEvent': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORVERTICALBLANKEVENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetGammaRamp': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETGAMMARAMP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetDeviceState': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETDEVICESTATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateDCFromMemory': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEDCFROMMEMORY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyDCFromMemory': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYDCFROMMEMORY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetContextSchedulingPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETCONTEXTSCHEDULINGPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetContextSchedulingPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETCONTEXTSCHEDULINGPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetProcessSchedulingPriorityClass': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="D3DKMT_SCHEDULINGPRIORITYCLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'D3DKMTGetProcessSchedulingPriorityClass': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3DKMT_SCHEDULINGPRIORITYCLASS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'D3DKMTReleaseProcessVidPnSourceOwners': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetScanLine': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETSCANLINE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTChangeSurfacePointer': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHANGESURFACEPOINTER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetQueuedLimit': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETQUEUEDLIMIT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPollDisplayChildren': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_POLLDISPLAYCHILDREN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTInvalidateActiveVidPn': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_INVALIDATEACTIVEVIDPN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckOcclusion': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKOCCLUSION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForIdle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORIDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckMonitorPowerState': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKMONITORPOWERSTATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckExclusiveOwnership': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'D3DKMTCheckVidPnExclusiveOwnership': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKVIDPNEXCLUSIVEOWNERSHIP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetDisplayPrivateDriverFormat': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETDISPLAYPRIVATEDRIVERFORMAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSharedPrimaryLockNotification': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SHAREDPRIMARYLOCKNOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSharedPrimaryUnLockNotification': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SHAREDPRIMARYUNLOCKNOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateKeyedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEKEYEDMUTEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenKeyedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENKEYEDMUTEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyKeyedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYKEYEDMUTEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTAcquireKeyedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ACQUIREKEYEDMUTEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTReleaseKeyedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_RELEASEKEYEDMUTEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateKeyedMutex2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEKEYEDMUTEX2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenKeyedMutex2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENKEYEDMUTEX2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTAcquireKeyedMutex2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ACQUIREKEYEDMUTEX2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTReleaseKeyedMutex2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_RELEASEKEYEDMUTEX2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTConfigureSharedResource': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CONFIGURESHAREDRESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetOverlayState': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETOVERLAYSTATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckSharedResourceAccess': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKSHAREDRESOURCEACCESS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOfferAllocations': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OFFERALLOCATIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTReclaimAllocations': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_RECLAIMALLOCATIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateOutputDupl': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATE_OUTPUTDUPL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyOutputDupl': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROY_OUTPUTDUPL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplGetFrameInfo': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPL_GET_FRAMEINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplGetMetaData': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPL_METADATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplGetPointerShapeData': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPL_GET_POINTER_SHAPE_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplReleaseFrame': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPL_RELEASE_FRAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplPresent': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPLPRESENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTEnumAdapters': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ENUMADAPTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTEnumAdapters2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ENUMADAPTERS2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenAdapterFromLuid': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENADAPTERFROMLUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryRemoteVidPnSourceFromGdiDisplayName': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYREMOTEVIDPNSOURCEFROMGDIDISPLAYNAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetVidPnSourceOwner1': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETVIDPNSOURCEOWNER1", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForVerticalBlankEvent2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORVERTICALBLANKEVENT2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetSyncRefreshCountWaitTarget': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETSYNCREFRESHCOUNTWAITTARGET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetDWMVerticalBlankEvent': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETVERTICALBLANKEVENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPresentMultiPlaneOverlay': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_PRESENT_MULTIPLANE_OVERLAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetSharedResourceAdapterLuid': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETSHAREDRESOURCEADAPTERLUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckMultiPlaneOverlaySupport': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKMULTIPLANEOVERLAYSUPPORT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetContextInProcessSchedulingPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETCONTEXTINPROCESSSCHEDULINGPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetContextInProcessSchedulingPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETCONTEXTINPROCESSSCHEDULINGPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTMakeResident': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_MAKERESIDENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTEvict': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_EVICT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForSynchronizationObjectFromCpu': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORSYNCHRONIZATIONOBJECTFROMCPU", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSignalSynchronizationObjectFromCpu': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMCPU", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTWaitForSynchronizationObjectFromGpu': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_WAITFORSYNCHRONIZATIONOBJECTFROMGPU", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSignalSynchronizationObjectFromGpu': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMGPU", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSignalSynchronizationObjectFromGpu2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMGPU2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreatePagingQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEPAGINGQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyPagingQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_DESTROYPAGINGQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTLock2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_LOCK2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUnlock2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_UNLOCK2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTInvalidateCache': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_INVALIDATECACHE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTMapGpuVirtualAddress': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_MAPGPUVIRTUALADDRESS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTReserveGpuVirtualAddress': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_RESERVEGPUVIRTUALADDRESS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTFreeGpuVirtualAddress': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_FREEGPUVIRTUALADDRESS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUpdateGpuVirtualAddress': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_UPDATEGPUVIRTUALADDRESS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetResourcePresentPrivateDriverData': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_GETRESOURCEPRESENTPRIVATEDRIVERDATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateContextVirtual': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATECONTEXTVIRTUAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSubmitCommand': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITCOMMAND", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenSyncObjectFromNtHandle2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENSYNCOBJECTFROMNTHANDLE2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenSyncObjectNtHandleFromName': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENSYNCOBJECTNTHANDLEFROMNAME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryVideoMemoryInfo': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYVIDEOMEMORYINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTChangeVideoMemoryReservation': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHANGEVIDEOMEMORYRESERVATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTRegisterTrimNotification': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_REGISTERTRIMNOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUnregisterTrimNotification': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_UNREGISTERTRIMNOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckMultiPlaneOverlaySupport2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKMULTIPLANEOVERLAYSUPPORT2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPresentMultiPlaneOverlay2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_PRESENT_MULTIPLANE_OVERLAY2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTReclaimAllocations2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_RECLAIMALLOCATIONS2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetStablePowerState': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETSTABLEPOWERSTATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryClockCalibration': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYCLOCKCALIBRATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryVidPnExclusiveOwnership': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYVIDPNEXCLUSIVEOWNERSHIP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTAdjustFullscreenGamma': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_ADJUSTFULLSCREENGAMMA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetVidPnSourceHwProtection': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETVIDPNSOURCEHWPROTECTION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTMarkDeviceAsError': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_MARKDEVICEASERROR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTFlushHeapTransitions': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_FLUSHHEAPTRANSITIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetHwProtectionTeardownRecovery': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETHWPROTECTIONTEARDOWNRECOVERY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryProcessOfferInfo': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYPROCESSOFFERINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTTrimProcessCommitment': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_TRIMPROCESSCOMMITMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTUpdateAllocationProperty': SimTypeFunction([SimTypePointer(SimTypeRef("D3DDDI_UPDATEALLOCPROPERTY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCheckMultiPlaneOverlaySupport3': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CHECKMULTIPLANEOVERLAYSUPPORT3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPresentMultiPlaneOverlay3': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_PRESENT_MULTIPLANE_OVERLAY3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetFSEBlock': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETFSEBLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryFSEBlock': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYFSEBLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateHwContext': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEHWCONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyHwContext': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYHWCONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSubmitCommandToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITCOMMANDTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSubmitWaitForSyncObjectsToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITWAITFORSYNCOBJECTSTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSubmitSignalSyncObjectsToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITSIGNALSYNCOBJECTSTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetAllocationPriority': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETALLOCATIONPRIORITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetMultiPlaneOverlayCaps': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GET_MULTIPLANE_OVERLAY_CAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetPostCompositionCaps': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GET_POST_COMPOSITION_CAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTPresentRedirected': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_PRESENT_REDIRECTED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetVidPnSourceOwner2': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SETVIDPNSOURCEOWNER2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSetMonitorColorSpaceTransform': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SET_COLORSPACE_TRANSFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCreateProtectedSession': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CREATEPROTECTEDSESSION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTDestroyProtectedSession': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_DESTROYPROTECTEDSESSION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryProtectedSessionStatus': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYPROTECTEDSESSIONSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTQueryProtectedSessionInfoFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_QUERYPROTECTEDSESSIONINFOFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenProtectedSessionFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENPROTECTEDSESSIONFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTGetProcessDeviceRemovalSupport': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_GETPROCESSDEVICEREMOVALSUPPORT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOpenKeyedMutexFromNtHandle': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OPENKEYEDMUTEXFROMNTHANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTRegisterVailProcess': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTCancelPresents': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_CANCEL_PRESENTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
    }

lib.set_prototypes(prototypes)
