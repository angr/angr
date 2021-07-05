from . import Analysis
from ..sim_type import SimCppClass, SimTypeCppFunction, SimTypePointer


class ClassIdentifier(Analysis):
    # This is a class identifier for non stripped or partially stripped binaries
    def __init__(self):
        if "CFGFast" not in self.project.kb.cfgs:
            self.project.analyses.CFGFast(cross_references=True)
        self.classes = {}
        vtable_analysis = self.project.analyses.VtableFinder()
        self.vtables_list = vtable_analysis.vtables_list
        self._analyze()

    def _analyze(self):
        # Assigning function to classes
        for func_addr, func in self.project.kb.functions.items():
            if func.is_plt:
                continue
            col_ind = func.demangled_name.rfind("::")
            class_name = func.demangled_name[:col_ind]
            if class_name.startswith("non-virtual thunk for "):
                class_name = class_name[len("non-virtual thunk for ") :]
            if col_ind != -1:
                if class_name not in self.classes:
                    ctor = False
                    if func.demangled_name.find("{ctor}"):
                        ctor = True
                    function_members = {
                        func.addr: SimTypeCppFunction(
                            [], None, label=func.demangled_name, ctor=ctor
                        )
                    }
                    new_class = SimCppClass(
                        name=class_name, function_members=function_members
                    )
                    self.classes[class_name] = new_class

                else:
                    ctor = False
                    if func.demangled_name.find("{ctor}"):
                        ctor = True
                    cur_class = self.classes[class_name]
                    cur_class.function_members[func.addr] = SimTypeCppFunction(
                        [], None, label=func.demangled_name, ctor=ctor
                    )

        # Assigning a vtable to a class
        for vtable in self.vtables_list:
            for ref in self.project.kb.xrefs.xrefs_by_dst[vtable.vaddr]:
                vtable_calling_func = self.project.kb.functions.floor_func(ref.ins_addr)
                tmp_col_ind = vtable_calling_func.demangled_name.rfind("::")
                possible_constructor_class_name = vtable_calling_func.demangled_name[
                    :tmp_col_ind
                ]
                if (
                    "ctor" in vtable_calling_func.demangled_name
                    and possible_constructor_class_name in self.classes
                ):
                    self.classes[possible_constructor_class_name].vtable_ptrs.append(
                        vtable.vaddr
                    )


from angr.analyses import AnalysesHub

AnalysesHub.register_default("ClassIdentifier", ClassIdentifier)
