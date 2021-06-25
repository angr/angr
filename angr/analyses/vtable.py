from . import Analysis
from . import register_analysis


class Vtable:
    def __init__(self, vaddr, size, func_addrs=None):
        self.vaddr = vaddr
        self.size = size
        self.func_addrs = func_addrs if func_addrs else []


class VtableFinder(Analysis):
    def __init__(self):
        self.cfg = self.project.analyses.CFGFast(cross_references=True)
        self.find_vtables()

    def is_cross_referenced(self, addr):
        if addr in self.cfg.kb.xrefs.xrefs_by_dst:
            return True
        else:
            return False

    def is_function(self, addr):
        if addr in self.cfg.kb.functions:
            return True
        else:
            return False

    def find_vtables(self):
        list_vtables = []
        in_vtable = False
        cur_vtable = None
        for sec in self.project.loader.main_object.sections:
            if sec.name in ['.data.rel.ro', '.rodata', '.data']:
                for offset in range(0, sec.memsize, self.project.arch.bytes):
                    cur_addr = sec.vaddr + offset
                    possible_func_addr = self.project.loader.memory.unpack_word(cur_addr)
                    # Check if this address is referenced in the code segment
                    if self.is_cross_referenced(cur_addr) and not in_vtable:
                        #check if it is also a function
                        if self.is_function(possible_func_addr):
                            #found a vtable start_addr
                            in_vtable = True
                            cur_vtable = Vtable(cur_addr, self.project.arch.bytes)
                            cur_vtable.func_addrs.append(possible_func_addr)
                            list_vtables.append(cur_vtable)
                    elif in_vtable and self.is_function(possible_func_addr) and not self.is_cross_referenced(cur_addr):
                        cur_vtable.func_addrs.append(possible_func_addr)
                        cur_vtable.size += self.project.arch.bytes
                    elif in_vtable and (not self.is_function(possible_func_addr) or self.is_cross_referenced(cur_addr)):
                        in_vtable = False
                        cur_vtable = None

        return list_vtables

from angr.analyses import AnalysesHub
AnalysesHub.register_default('VtableFinder', VtableFinder)

