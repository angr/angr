from __future__ import annotations

from archinfo import Arch

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass


class DecompilationPreset:
    """
    A DecompilationPreset provides a preconfigured set of optimizations and configurations for the Decompiler analysis.
    """

    def __init__(self, name: str, opt_passes: list[type[OptimizationPass]]):
        self.name = name
        self.opt_passes = opt_passes

    def get_optimization_passes(self, arch: Arch | str, platform: str | None, additional_opts=None, disable_opts=None):
        if isinstance(arch, Arch):
            arch = arch.name

        if platform is not None:
            platform = platform.lower()
        if platform == "win32":
            platform = "windows"  # sigh

        passes = []
        additional_opts = additional_opts or []
        disable_opts = disable_opts or []
        for pass_ in self.opt_passes + additional_opts:
            if pass_ in disable_opts:
                continue
            if (pass_.ARCHES is None or arch in pass_.ARCHES) and (
                pass_.PLATFORMS is None or platform is None or platform in pass_.PLATFORMS
            ):
                passes.append(pass_)

        return passes
