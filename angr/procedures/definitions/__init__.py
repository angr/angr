import copy
import os

from ..stubs.ReturnUnconstrained import ReturnUnconstrained
from ...calling_conventions import DEFAULT_CC
from ...misc import autoimport

SIM_LIBRARIES = {}

class SimLibrary(object):
    def __init__(self):
        self.procedures = {}
        self.non_returning = set()
        self.prototypes = {}
        self.default_ccs = {}
        self.names = []

    @property
    def name(self):
        return self.names[0] if self.names else '??????'

    def set_library_names(self, *names):
        for name in names:
            self.names.append(name)
            SIM_LIBRARIES[name] = self

    def set_default_cc(self, arch_name, cc_cls):
        self.default_ccs[arch_name] = cc_cls

    def set_non_returning(self, *names):
        for name in names:
            self.non_returning.add(name)

    def set_prototype(self, name, proto):
        self.prototypes[name] = proto

    def add(self, name, proc_cls, **kwargs):
        self.procedures[name] = proc_cls(display_name=name, **kwargs)

    def add_all_from_dict(self, dictionary, **kwargs):
        for name, procedure in dictionary.iteritems():
            self.add(name, procedure, **kwargs)

    def add_alias(self, name, *alt_names):
        old_procedure = self.procedures[name]
        for alt in alt_names:
            new_procedure = copy.deepcopy(old_procedure)
            new_procedure.display_name = alt
            self.procedures[alt] = new_procedure

    def _apply_metadata(self, proc, arch):
        if proc.cc is None and arch.name in self.default_ccs:
            proc.cc = self.default_ccs[arch.name]()
        if proc.display_name in self.prototypes:
            if proc.cc is None:
                proc.cc = DEFAULT_CC[arch.name]()
            proc.cc.func_ty = self.prototypes[proc.display_name]
        if proc.display_name in self.non_returning:
            proc.returns = False

    def get(self, name, arch):
        if name in self.procedures:
            proc = copy.deepcopy(self.procedures[name])
            self._apply_metadata(proc, arch)
            return proc
        else:
            return self.get_stub(name, arch)

    def get_stub(self, name, arch):
        proc = ReturnUnconstrained(display_name=name)
        self._apply_metadata(proc, arch)
        return proc

    def has_metadata(self, name):
        return self.has_implementation(name) or \
            name in self.non_returning or \
            name in self.prototypes

    def has_implementation(self, name):
        return name in self.procedures

for _ in autoimport.auto_import_modules('angr.procedures.definitions', os.path.dirname(os.path.realpath(__file__))):
    pass
