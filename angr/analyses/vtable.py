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
        self.analyze()

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

    def analyze(self):
        # finding candidate starting vtable addresses
        # "current location is referenced from a code segment andits value is a pointer to a function,
        # then it is marked as astart of vtable"
        # taken from - Reconstruction of Class Hierarchies for Decompilation of C++ Programs
        list_vtables = []
        for sec in self.project.loader.main_object.sections:
            if sec.name in ['.data.rel.ro', '.rodata', '.data']:
                for offset in range(0, sec.memsize, self.project.arch.bytes):
                    cur_addr = sec.vaddr + offset
                    possible_func_addr = self.project.loader.memory.unpack_word(cur_addr)
                    # check if this address is referenced in the code segment
                    if self.is_cross_referenced(cur_addr):
                        # check if it is also a function, if so then it is possibly a vtable start
                        if self.is_function(possible_func_addr):
                            new_vtable = self.create_extract_vtable(cur_addr, sec.memsize)
                            list_vtables.append(new_vtable)

        print(list_vtables)
        import ipdb;ipdb.set_trace()
        return list_vtables

    def create_extract_vtable(self, start_addr, sec_size):
        # using the starting address extracting the vtable
        # "Other elements of vtable must be unreferenced pointers to function"
        # "Vtable ends with the first location that is either referencedfrom the program code, or is not a pointer to a function"
        # taken from - Reconstruction of Class Hierarchies for Decompilation of C++ Programs
        first_func_addr = self.project.loader.memory.unpack_word(start_addr)
        cur_vtable = Vtable(start_addr, self.project.arch.bytes, [first_func_addr])
        for cur_addr in range(start_addr + self.project.arch.bytes, start_addr+sec_size, self.project.arch.bytes):
            possible_func_addr = self.project.loader.memory.unpack_word(cur_addr)
            if self.is_function(possible_func_addr) and not self.is_cross_referenced(cur_addr):
                cur_vtable.func_addrs.append(possible_func_addr)
                cur_vtable.size += self.project.arch.bytes
            elif not self.is_function(possible_func_addr) or self.is_cross_referenced(cur_addr):
                return cur_vtable


from angr.analyses import AnalysesHub
AnalysesHub.register_default('VtableFinder', VtableFinder)

