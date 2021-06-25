from . import Analysis
from . import register_analysis


class VtableFinder(Analysis):
    def __init__(self):
        self.cfg = self.project.analyses.CFGFast(cross_references=True)
        self.find_vtables()

    def find_vtables(self):
        list_vtables = []
        for sec in self.project.loader.main_object.sections:
            if sec.name in ['.data.rel.ro']:#'.rodata',, '.data'
                for offset in range(0,sec.memsize,self.project.arch.bytes):
                    possible_func_addr = self.project.loader.memory.unpack_word(sec.vaddr + offset)
                    # Check if this address is referenced in the code segment and is a function
                    import ipdb;
                    ipdb.set_trace()

        return list_vtables


from angr.analyses import AnalysesHub
AnalysesHub.register_default('VtableFinder', VtableFinder)

