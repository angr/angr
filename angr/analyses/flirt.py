from functools import partial
from typing import Union, TYPE_CHECKING
import logging

try:
    import nampa
except ImportError:
    nampa = None

from ..flirt import FlirtSignature
from .analysis import Analysis

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(name=__name__)


class FlirtAnalysis(Analysis):
    def __init__(self, sig: Union[FlirtSignature,str]):
        if nampa is None:
            raise ImportError("Cannot import nampa. Please install nampa first before using %s" % self.__class__)

        if isinstance(sig, str):
            # this is a file path
            self.sig = FlirtSignature(self.project.arch.name.lower(), self.project.simos.name.lower(), "Temporary",
                                      sig, None)
        else:
            self.sig = sig

        self._match_all()

    def _match_all(self):
        # match each function
        with open(self.sig.sig_path, "rb") as sigfile:
            flirt = nampa.parse_flirt_file(sigfile)
            for func in self.project.kb.functions.values():
                func: 'Function'
                if func.is_simprocedure or func.is_plt:
                    continue
                if not func.is_default_name:
                    # it already has a name. skip
                    continue

                start = func.addr

                max_block_addr = max(func.block_addrs_set)
                end_block = func.get_block(max_block_addr)
                end = max_block_addr + end_block.size

                # load all bytes
                func_bytes = self.project.loader.memory.load(start, end - start + 0x100)
                _callback = partial(self._on_func_matched, func)
                nampa.match_function(flirt, func_bytes, start, _callback)

    def _on_func_matched(self, func: 'Function', base_addr: int, flirt_func: 'nampa.FlirtFunction'):
        func_addr = base_addr + flirt_func.offset
        if func_addr != base_addr:
            # get the correct function
            try:
                func = self.kb.functions.get_by_addr(func_addr)
            except KeyError:
                # the function is not found
                _l.warning("FlirtAnalysis identified a function at %#x but it does not exist in function manager.",
                           func_addr)
                return

        if func.is_default_name:
            # set the function name
            # TODO: Make sure function names do not conflict with existing ones
            _l.debug("Identified %s @ %#x (%#x-%#x)", flirt_func.name, func_addr, base_addr, flirt_func.offset)
            if flirt_func.name != "?":
                func.name = flirt_func.name
            else:
                func.name = "unknown_func"
            func.is_default_name = False
            func.from_signature = "flirt"


from angr.analyses import AnalysesHub
AnalysesHub.register_default('Flirt', FlirtAnalysis)
