
import logging

from . import Analysis, register_analysis

from .. import SIM_PROCEDURES
from ..errors import AngrValueError

l = logging.getLogger("angr.analyses.static_hooker")

class StaticHooker(Analysis):
    """
    This analysis works on statically linked binaries - it finds the library functions statically
    linked into the binary and hooks them with the appropraite simprocedures.

    Right now it only works on libc functions and unstripped binaries, but hey! There's room to
    grow!
    """

    def __init__(self):
        self.results = {}

        if self.project.loader.main_bin.linking == 'dynamic':
            raise AngrValueError('StaticHooker only works on static binaries!')

        for func in self.project.loader.main_bin._symbol_cache.values():
            if not func.is_function: continue
            try:
                self.project.hook(func.rebased_addr, SIM_PROCEDURES['libc.so.6'][func.name])
            except:     # pylint: disable=bare-except
                l.debug("Failed to hook %s at %#x", func.name, func.rebased_addr)
            else:
                l.info("Hooked %s at %#x", func.name, func.rebased_addr)
                self.results[func.rebased_addr] = SIM_PROCEDURES['libc.so.6'][func.name]

register_analysis(StaticHooker, 'StaticHooker')
