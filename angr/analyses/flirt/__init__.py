from __future__ import annotations
from .flirt import FlirtAnalysis
from .flirt_sig import FlirtSignature, FlirtSignatureParsed, FlirtSignatureError
from .consts import FLIRT_ARCH_TO_ARCHNAME, FLIRT_OS_TO_OSNAME, FlirtAppType, FlirtOSType


def flirt_arch_to_arch_name(flirt_arch: int, app_types: int) -> str:
    """
    Convert FLIRT architecture ID to architecture name.

    :param flirt_arch: FLIRT architecture ID.
    :param app_types: FLIRT application types.
    :return: Architecture name.
    """
    try:
        arches = FLIRT_ARCH_TO_ARCHNAME[flirt_arch]
    except KeyError:
        return "Unknown"
    if app_types & FlirtAppType.APP_32_BIT and 32 in arches:
        return arches[32]
    if app_types & FlirtAppType.APP_64_BIT and 64 in arches:
        return arches[64]
    return "Unknown"


def flirt_os_type_to_os_name(os_type: int) -> str:
    """
    Convert FLIRT OS type to OS name.

    :param os_type: FLIRT OS type.
    :return: OS name.
    """
    try:
        v = FlirtOSType(os_type)
        return FLIRT_OS_TO_OSNAME.get(v, v.name)
    except ValueError:
        return "UnknownOS"


__all__ = [
    "FlirtAnalysis",
    "FlirtSignature",
    "FlirtSignatureError",
    "FlirtSignatureParsed",
    "flirt_arch_to_arch_name",
    "flirt_os_type_to_os_name",
]
