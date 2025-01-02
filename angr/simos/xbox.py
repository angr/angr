from __future__ import annotations

try:
    import xbe
except ImportError:
    xbe = None

from angr.procedures import SIM_PROCEDURES
from angr.calling_conventions import SimCCStdcall
from .simos import SimOS


class SimXbox(SimOS):
    """
    Environment for the original Xbox subsystem (x86, 32-bit).
    """

    def __init__(self, project):
        super().__init__(project, name="Xbox")

    def configure_project(self):
        super().configure_project()

        if xbe is None:
            raise ImportError("Please install pyxbe to use the SimXbox environment")

        stub_cls = SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        for export_no, export_name in xbe.XbeKernelImage.exports.items():
            addr = 0x8000_0000 + export_no
            cc = SimCCStdcall(self.project.arch)
            hooker = stub_cls(cc=cc, display_name=export_name, library_name="xboxkrnl.exe", is_stub=True)
            self.project.hook(addr, hooker, replace=True)
