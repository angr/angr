import copy
import os
import archinfo
from collections import defaultdict
import logging

from ..stubs.ReturnUnconstrained import ReturnUnconstrained
from ..stubs.syscall_stub import syscall as stub_syscall
from ...calling_conventions import DEFAULT_CC
from ...misc import autoimport

l = logging.getLogger("angr.procedures.definitions")
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

    def copy(self):
        o = SimLibrary()
        o.procedures = dict(self.procedures)
        o.non_returning = set(self.non_returning)
        o.prototypes = dict(self.prototypes)
        o.default_ccs = dict(self.default_ccs)
        o.names = list(self.names)
        return o

    def update(self, other):
        self.procedures.update(other.procedures)
        self.non_returning.update(other.non_returning)
        self.prototypes.update(other.prototypes)
        self.default_ccs.update(other.default_ccs)

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
        self.default_cc_mapping = {}

    fallback_proc = stub_syscall

    def copy(self):
        o = SimSyscallLibrary()
        o.procedures = dict(self.procedures)
        o.non_returning = set(self.non_returning)
        o.prototypes = dict(self.prototypes)
        o.default_ccs = dict(self.default_ccs)
        o.names = list(self.names)
        o.syscall_number_mapping = defaultdict(dict, self.syscall_number_mapping) # {abi: {number: name}}
        o.default_cc_mapping = dict(self.default_cc_mapping) # {abi: cc}
        return o

    def update(self, other):
        super(SimSyscallLibrary, self).update(other)
        self.syscall_number_mapping.update(other.syscall_number_mapping)
        self.default_cc_mapping.update(other.default_cc_mapping)

    def minimum_syscall_number(self, abi):
        if abi not in self.syscall_number_mapping or \
                not self.syscall_number_mapping[abi]:
            return 0
        return min(self.syscall_number_mapping[abi])

    def maximum_syscall_number(self, abi):
        if abi not in self.syscall_number_mapping or \
                not self.syscall_number_mapping[abi]:
            return 0
        return max(self.syscall_number_mapping[abi])

    def add_number_mapping(self, abi, number, name):
        self.syscall_number_mapping[abi][number] = name

    def add_number_mapping_from_dict(self, abi, mapping):
        self.syscall_number_mapping[abi].update(mapping)

    def set_abi_cc(self, abi, cc_cls):
        self.default_cc_mapping[abi] = cc_cls

    def _canonicalize(self, number, arch, abi_list):
        if type(arch) is str:
            arch = archinfo.arch_from_id(arch)
        if type(number) is str:
            return number, arch, None
        for abi in abi_list:
            mapping = self.syscall_number_mapping[abi]
            if number in mapping:
                return mapping[number], arch, abi
        return 'sys_%d' % number, arch, None

    def _apply_numerical_metadata(self, proc, number, arch, abi):
        proc.syscall_number = number
        proc.abi = abi
        if abi in self.default_cc_mapping:
            cc = self.default_cc_mapping[abi](arch)
            if proc.cc is not None:
                cc.func_ty = proc.cc.func_ty
            proc.cc = cc

    # pylint: disable=arguments-differ
    def get(self, number, arch, abi_list=()):
        name, arch, abi = self._canonicalize(number, arch, abi_list)
        proc = super(SimSyscallLibrary, self).get(name, arch)
        self._apply_numerical_metadata(proc, number, arch, abi)
        return proc

    def get_stub(self, number, arch, abi_list=()):
        name, arch, abi = self._canonicalize(number, arch, abi_list)
        proc = super(SimSyscallLibrary, self).get_stub(name, arch)
        self._apply_numerical_metadata(proc, number, arch, abi)
        l.warn("unsupported syscall: %s", number)
        return proc

    def has_metadata(self, number, arch, abi_list=()):
        name, _, _ = self._canonicalize(number, arch, abi_list)
        return super(SimSyscallLibrary, self).has_metadata(name)

    def has_implementation(self, number, arch, abi_list=()):
        name, _, _ = self._canonicalize(number, arch, abi_list)
        return super(SimSyscallLibrary, self).has_implementation(name)

for _ in autoimport.auto_import_modules('angr.procedures.definitions', os.path.dirname(os.path.realpath(__file__))):
    pass
