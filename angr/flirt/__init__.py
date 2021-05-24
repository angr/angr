# This submodule stores and manages FLIRT signatures

from typing import Optional


class FlirtSignature:
    def __init__(self, arch_name: str, platform: str, sig_name: str, sig_path: str, uniquestr_path: Optional[str]):
        self.arch_name = arch_name
        self.platform = platform
        self.sig_name = sig_name
        self.sig_path = sig_path
        self.uniquestr_path = uniquestr_path


FS = FlirtSignature

FLIRT_SIGNATURES = {
}
