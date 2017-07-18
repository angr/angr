import copy
import os
import archinfo
from collections import defaultdict

from ..stubs.ReturnUnconstrained import ReturnUnconstrained
from ..stubs.syscall_stub import syscall as stub_syscall
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

    fallback_cc = DEFAULT_CC
    fallback_proc = ReturnUnconstrained

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
            proc.cc = self.default_ccs[arch.name](arch)
        if proc.display_name in self.prototypes:
            if proc.cc is None:
                proc.cc = self.fallback_cc[arch.name]()
            proc.cc.func_ty = self.prototypes[proc.display_name]
        if proc.display_name in self.non_returning:
            proc.returns = False
        proc.library_name = self.name

    def get(self, name, arch):
        if type(arch) is str:
            arch = archinfo.arch_from_id(arch)
        if name in self.procedures:
            proc = copy.deepcopy(self.procedures[name])
            self._apply_metadata(proc, arch)
            return proc
        else:
            return self.get_stub(name, arch)

    def get_stub(self, name, arch):
        proc = self.fallback_proc(display_name=name, is_stub=True)
        self._apply_metadata(proc, arch)
        return proc

    def has_metadata(self, name):
        return self.has_implementation(name) or \
            name in self.non_returning or \
            name in self.prototypes

    def has_implementation(self, name):
        return name in self.procedures


class SimSyscallLibrary(SimLibrary):
    def __init__(self):
        super(SimSyscallLibrary, self).__init__()
        self.syscall_number_mapping = defaultdict(dict)
        self.ranged_default_ccs = defaultdict(list)

    fallback_proc = stub_syscall

    def maximum_syscall_number(self, arch_name):
        return max(self.syscall_number_mapping[arch_name])

    def add_number_mapping(self, arch_name, number, name):
        self.syscall_number_mapping[arch_name][number] = name

    def add_number_mapping_from_dict(self, arch_name, mapping):
        self.syscall_number_mapping[arch_name].update(mapping)

    def set_default_cc_ranged(self, arch_name, min_num, max_num, cc_cls):
        self.ranged_default_ccs[arch_name].append((min_num, max_num, cc_cls))

    def _canonicalize(self, number, arch):
        if type(arch) is str:
            arch = archinfo.arch_from_id(arch)
        if type(number) is str:
            return number, arch
        mapping = self.syscall_number_mapping[arch.name]
        if number in mapping:
            return mapping[number], arch
        else:
            return 'sys_%d' % number, arch

    def _apply_numerical_metadata(self, proc, number, arch):
        proc.syscall_number = number
        for min_num, max_num, cc_cls in self.ranged_default_ccs[arch.name]:
            if min_num <= number <= max_num:
                new_cc = cc_cls(arch)
                old_cc = proc.cc
                if old_cc is not None:
                    new_cc.func_ty = old_cc.func_ty
                proc.cc = new_cc
                break

    def get(self, number, arch):
        name, arch = self._canonicalize(number, arch)
        proc = super(SimSyscallLibrary, self).get(name, arch)
        self._apply_numerical_metadata(proc, number, arch)
        return proc

    def get_stub(self, number, arch):
        name, arch = self._canonicalize(number, arch)
        proc = super(SimSyscallLibrary, self).get_stub(name, arch)
        self._apply_numerical_metadata(proc, number, arch)
        return proc

    def has_metadata(self, number, arch):
        name, arch = self._canonicalize(number, arch)
        return super(SimSyscallLibrary, self).has_metadata(name)

    def has_implementation(self, number, arch):
        name, arch = self._canonicalize(number, arch)
        return super(SimSyscallLibrary, self).has_implementation(name)

for _ in autoimport.auto_import_modules('angr.procedures.definitions', os.path.dirname(os.path.realpath(__file__))):
    pass
