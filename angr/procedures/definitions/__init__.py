import copy
import os
import archinfo
from collections import defaultdict
import logging
import inspect
from typing import Optional, Dict, Type, TYPE_CHECKING

import itanium_demangler

from ...sim_type import parse_cpp_file, SimTypeFunction
from ...calling_conventions import DEFAULT_CC
from ...misc import autoimport
from ...misc.ux import once
from ...sim_type import parse_file
from ..stubs.ReturnUnconstrained import ReturnUnconstrained
from ..stubs.syscall_stub import syscall as stub_syscall

if TYPE_CHECKING:
    from angr.calling_conventions import SimCCSyscall


l = logging.getLogger(name=__name__)
SIM_LIBRARIES: Dict[str,'SimLibrary'] = {}


class SimLibrary:
    """
    A SimLibrary is the mechanism for describing a dynamic library's API, its functions and metadata.

    Any instance of this class (or its subclasses) found in the ``angr.procedures.definitions`` package will be
    automatically picked up and added to ``angr.SIM_LIBRARIES`` via all its names.

    :ivar fallback_cc:      A mapping from architecture to the default calling convention that should be used if no
                            other information is present. Contains some sane defaults for linux.
    :ivar fallback_proc:    A SimProcedure class that should be used to provide stub procedures. By default,
                            ``ReturnUnconstrained``.
    """
    def __init__(self):
        self.procedures = {}
        self.non_returning = set()
        self.prototypes: Dict[str,SimTypeFunction] = {}
        self.default_ccs = {}
        self.names = []
        self.fallback_cc = dict(DEFAULT_CC)
        self.fallback_proc = ReturnUnconstrained

    def copy(self):
        """
        Make a copy of this SimLibrary, allowing it to be mutated without affecting the global version.

        :return:    A new SimLibrary object with the same library references but different dict/list references
        """
        o = SimLibrary()
        o.procedures = dict(self.procedures)
        o.non_returning = set(self.non_returning)
        o.prototypes = dict(self.prototypes)
        o.default_ccs = dict(self.default_ccs)
        o.names = list(self.names)
        return o

    def update(self, other):
        """
        Augment this SimLibrary with the information from another SimLibrary

        :param other:   The other SimLibrary
        """
        self.procedures.update(other.procedures)
        self.non_returning.update(other.non_returning)
        self.prototypes.update(other.prototypes)
        self.default_ccs.update(other.default_ccs)

    @property
    def name(self):
        """
        The first common name of this library, e.g. libc.so.6, or '??????' if none are known.
        """
        return self.names[0] if self.names else '??????'

    def set_library_names(self, *names):
        """
        Set some common names of this library by which it may be referred during linking

        :param names:   Any number of string library names may be passed as varargs.
        """
        for name in names:
            self.names.append(name)
            SIM_LIBRARIES[name] = self

    def set_default_cc(self, arch_name, cc_cls):
        """
        Set the default calling convention used for this library under a given architecture

        :param arch_name:   The string name of the architecture, i.e. the ``.name`` field from archinfo.
        :parm cc_cls:       The SimCC class (not an instance!) to use
        """
        arch_name = archinfo.arch_from_id(arch_name).name
        self.default_ccs[arch_name] = cc_cls

    def set_non_returning(self, *names):
        """
        Mark some functions in this class as never returning, i.e. loops forever or terminates execution

        :param names:   Any number of string function names may be passed as varargs
        """
        for name in names:
            self.non_returning.add(name)

    def set_prototype(self, name, proto):
        """
        Set the prototype of a function in the form of a SimTypeFunction containing argument and return types

        :param name:    The name of the function as a string
        :param proto:   The prototype of the function as a SimTypeFunction
        """
        self.prototypes[name] = proto

    def set_prototypes(self, protos):
        """
        Set the prototypes of many functions

        :param protos:   Dictionary mapping function names to SimTypeFunction objects
        """
        self.prototypes.update(protos)

    def set_c_prototype(self, c_decl):
        """
        Set the prototype of a function in the form of a C-style function declaration.

        :param str c_decl: The C-style declaration of the function.
        :return:           A tuple of (function name, function prototype)
        :rtype:            tuple
        """

        parsed = parse_file(c_decl)
        parsed_decl = parsed[0]
        if not parsed_decl:
            raise ValueError('Cannot parse the function prototype.')
        func_name, func_proto = next(iter(parsed_decl.items()))

        self.set_prototype(func_name, func_proto)

        return func_name, func_proto

    def add(self, name, proc_cls, **kwargs):
        """
        Add a function implementation fo the library.

        :param name:        The name of the function as a string
        :param proc_cls:    The implementation of the function as a SimProcedure _class_, not instance
        :param kwargs:      Any additional parameters to the procedure class constructor may be passed as kwargs
        """
        self.procedures[name] = proc_cls(display_name=name, **kwargs)

    def add_all_from_dict(self, dictionary, **kwargs):
        """
        Batch-add function implementations to the library.

        :param dictionary:  A mapping from name to procedure class, i.e. the first two arguments to add()
        :param kwargs:      Any additional kwargs will be passed to the constructors of _each_ procedure class
        """
        for name, procedure in dictionary.items():
            self.add(name, procedure, **kwargs)

    def add_alias(self, name, *alt_names):
        """
        Add some duplicate names for a given function. The original function's implementation must already be
        registered.

        :param name:        The name of the function for which an implementation is already present
        :param alt_names:   Any number of alternate names may be passed as varargs
        """
        old_procedure = self.procedures[name]
        for alt in alt_names:
            new_procedure = copy.deepcopy(old_procedure)
            new_procedure.display_name = alt
            self.procedures[alt] = new_procedure
            if name in self.prototypes:
                self.prototypes[alt] = self.prototypes[name]
            if name in self.non_returning:
                self.non_returning.add(alt)


    def _apply_metadata(self, proc, arch):
        if proc.cc is None and arch.name in self.default_ccs:
            proc.cc = self.default_ccs[arch.name](arch)
        if proc.cc is None and arch.name in self.fallback_cc:
            proc.cc = self.fallback_cc[arch.name](arch)
        if proc.display_name in self.prototypes:
            proc.prototype = self.prototypes[proc.display_name].with_arch(arch)
            if proc.prototype.arg_names is None:
                # Use inspect to extract the parameters from the run python function
                proc.prototype.arg_names = inspect.getfullargspec(proc.run).args[1:]
            if not proc.ARGS_MISMATCH:
                proc.num_args = len(proc.prototype.args)
        if proc.display_name in self.non_returning:
            proc.returns = False
        proc.library_name = self.name

    def get(self, name, arch):
        """
        Get an implementation of the given function specialized for the given arch, or a stub procedure if none exists.

        :param name:    The name of the function as a string
        :param arch:    The architecure to use, as either a string or an archinfo.Arch instance
        :return:        A SimProcedure instance representing the function as found in the library
        """
        if type(arch) is str:
            arch = archinfo.arch_from_id(arch)
        if name in self.procedures:
            proc = copy.deepcopy(self.procedures[name])
            self._apply_metadata(proc, arch)
            return proc
        else:
            return self.get_stub(name, arch)

    def get_stub(self, name, arch):
        """
        Get a stub procedure for the given function, regardless of if a real implementation is available. This will
        apply any metadata, such as a default calling convention or a function prototype.

        By stub, we pretty much always mean a ``ReturnUnconstrained`` SimProcedure with the appropriate display name
        and metadata set. This will appear in ``state.history.descriptions`` as ``<SimProcedure display_name (stub)>``

        :param name:    The name of the function as a string
        :param arch:    The architecture to use, as either a string or an archinfo.Arch instance
        :return:        A SimProcedure instance representing a plausable stub as could be found in the library.
        """
        proc = self.fallback_proc(display_name=name, is_stub=True)
        self._apply_metadata(proc, arch)
        return proc

    def get_prototype(self, name: str, arch=None) -> Optional[SimTypeFunction]:
        """
        Get a prototype of the given function name, optionally specialize the prototype to a given architecture.

        :param name:    Name of the function.
        :param arch:    The architecture to specialize to.
        :return:        Prototype of the function, or None if the prototype does not exist.
        """
        proto = self.prototypes.get(name, None)
        if proto is None:
            return None
        if arch is not None:
            return proto.with_arch(arch)
        return proto

    def has_metadata(self, name):
        """
        Check if a function has either an implementation or any metadata associated with it

        :param name:    The name of the function as a string
        :return:        A bool indicating if anything is known about the function
        """
        return self.has_implementation(name) or \
            name in self.non_returning or \
            name in self.prototypes

    def has_implementation(self, name):
        """
        Check if a function has an implementation associated with it

        :param name:    The name of the function as a string
        :return:        A bool indicating if an implementation of the function is available
        """
        return name in self.procedures

    def has_prototype(self, func_name):
        """
        Check if a function has a prototype associated with it.

        :param str func_name: The name of the function.
        :return:              A bool indicating if a prototype of the function is available.
        :rtype:               bool
        """

        return func_name in self.prototypes


class SimCppLibrary(SimLibrary):
    """
    SimCppLibrary is a specialized version of SimLibrary that will demangle C++ function names before looking for an
    implementation or prototype for it.
    """

    @staticmethod
    def _try_demangle(name):
        if name[0:2] == "_Z":
            try:
                ast = itanium_demangler.parse(name)
            except NotImplementedError:
                return name
            if ast:
                return str(ast)
        return name

    @staticmethod
    def _proto_from_demangled_name(name: str) -> Optional[SimTypeFunction]:
        """
        Attempt to extract arguments and calling convention information for a C++ function whose name was mangled
        according to the Itanium C++ ABI symbol mangling language.

        :param name:    The demangled function name.
        :return:        A prototype or None if a prototype cannot be found.
        """

        try:
            parsed, _ = parse_cpp_file(name, with_param_names=False)
        except ValueError:
            return None
        if not parsed:
            return None
        _, func_proto = next(iter(parsed.items()))
        return func_proto

    def get(self, name, arch):
        """
        Get an implementation of the given function specialized for the given arch, or a stub procedure if none exists.
        Demangle the function name if it is a mangled C++ name.

        :param str name:    The name of the function as a string
        :param arch:    The architecure to use, as either a string or an archinfo.Arch instance
        :return:        A SimProcedure instance representing the function as found in the library
        """
        demangled_name = self._try_demangle(name)
        if demangled_name not in self.procedures:
            return self.get_stub(name, arch)  # get_stub() might use the mangled name to derive the function prototype
        return super().get(demangled_name, arch)

    def get_stub(self, name, arch):
        """
        Get a stub procedure for the given function, regardless of if a real implementation is available. This will
        apply any metadata, such as a default calling convention or a function prototype. Demangle the function name
        if it is a mangled C++ name.

        :param str name:    The name of the function as a string
        :param arch:        The architecture to use, as either a string or an archinfo.Arch instance
        :return:            A SimProcedure instance representing a plausable stub as could be found in the library.
        """
        demangled_name = self._try_demangle(name)
        stub = super().get_stub(demangled_name, arch)
        # try to determine a prototype from the function name if possible
        if demangled_name != name:
            # itanium-mangled function name
            stub.prototype = self._proto_from_demangled_name(demangled_name)
            if stub.prototype is not None:
                stub.prototype = stub.prototype.with_arch(arch)
                if not stub.ARGS_MISMATCH:
                    stub.cc.num_args = len(stub.prototype.args)
                    stub.num_args = len(stub.prototype.args)
        return stub

    def get_prototype(self, name: str, arch=None) -> Optional[SimTypeFunction]:
        """
        Get a prototype of the given function name, optionally specialize the prototype to a given architecture. The
        function name will be demangled first.

        :param name:    Name of the function.
        :param arch:    The architecture to specialize to.
        :return:        Prototype of the function, or None if the prototype does not exist.
        """
        demangled_name = self._try_demangle(name)
        return super().get_prototype(demangled_name, arch=arch)

    def has_metadata(self, name):
        """
        Check if a function has either an implementation or any metadata associated with it. Demangle the function name
        if it is a mangled C++ name.

        :param name:    The name of the function as a string
        :return:        A bool indicating if anything is known about the function
        """
        name = self._try_demangle(name)
        return super().has_metadata(name)

    def has_implementation(self, name):
        """
        Check if a function has an implementation associated with it. Demangle the function name if it is a mangled C++
        name.

        :param str name:    A mangled function name.
        :return:            bool
        """
        return super().has_implementation(self._try_demangle(name))

    def has_prototype(self, func_name):
        """
        Check if a function has a prototype associated with it. Demangle the function name if it is a mangled C++ name.

        :param str name:    A mangled function name.
        :return:            bool
        """
        return super().has_prototype(self._try_demangle(func_name))


class SimSyscallLibrary(SimLibrary):
    """
    SimSyscallLibrary is a specialized version of SimLibrary for dealing not with a dynamic library's API but rather
    an operating system's syscall API. Because this interface is inherently lower-level than a dynamic library, many
    parts of this class has been changed to store data based on an "ABI name" (ABI = application binary interface,
    like an API but for when there's no programming language) instead of an architecture. An ABI name is just an
    arbitrary string with which a calling convention and a syscall numbering is associated.

    All the SimLibrary methods for adding functions still work, but now there's an additional layer on top that
    associates them with numbers.
    """
    def __init__(self):
        super().__init__()
        self.syscall_number_mapping: Dict[str,Dict[int,str]] = defaultdict(dict)  # keyed by abi
        self.syscall_name_mapping: Dict[str,Dict[str,int]] = defaultdict(dict)  # keyed by abi
        self.default_cc_mapping: Dict[str,Type['SimCCSyscall']] = {}  # keyed by abi
        self.syscall_prototypes: Dict[str,Dict[str,SimTypeFunction]] = defaultdict(dict)  # keyed by abi
        self.fallback_proc = stub_syscall

    def copy(self):
        o = SimSyscallLibrary()
        o.procedures = dict(self.procedures)
        o.non_returning = set(self.non_returning)
        o.prototypes = dict(self.prototypes)
        o.default_ccs = dict(self.default_ccs)
        o.names = list(self.names)
        o.syscall_number_mapping = defaultdict(dict, self.syscall_number_mapping) # {abi: {number: name}}
        o.syscall_name_mapping = defaultdict(dict, self.syscall_name_mapping) # {abi: {name: number}}
        o.syscall_prototypes = defaultdict(dict, self.syscall_prototypes) # as above
        o.default_cc_mapping = dict(self.default_cc_mapping) # {abi: cc}
        return o

    def update(self, other):
        super().update(other)
        self.syscall_number_mapping.update(other.syscall_number_mapping)
        self.syscall_name_mapping.update(other.syscall_name_mapping)
        self.default_cc_mapping.update(other.default_cc_mapping)

    def minimum_syscall_number(self, abi):
        """
        :param abi: The abi to evaluate
        :return:    The smallest syscall number known for the given abi
        """
        if abi not in self.syscall_number_mapping or \
                not self.syscall_number_mapping[abi]:
            return 0
        return min(self.syscall_number_mapping[abi])

    def maximum_syscall_number(self, abi):
        """
        :param abi: The abi to evaluate
        :return:    The largest syscall number known for the given abi
        """
        if abi not in self.syscall_number_mapping or \
                not self.syscall_number_mapping[abi]:
            return 0
        return max(self.syscall_number_mapping[abi])

    def add_number_mapping(self, abi, number, name):
        """
        Associate a syscall number with the name of a function present in the underlying SimLibrary

        :param abi:     The abi for which this mapping applies
        :param number:  The syscall number
        :param name:    The name of the function
        """
        self.syscall_number_mapping[abi][number] = name
        self.syscall_name_mapping[abi][name] = number

    def add_number_mapping_from_dict(self, abi, mapping):
        """
        Batch-associate syscall numbers with names of functions present in the underlying SimLibrary

        :param abi:     The abi for which this mapping applies
        :param mapping: A dict mapping syscall numbers to function names
        """
        self.syscall_number_mapping[abi].update(mapping)
        self.syscall_name_mapping[abi].update(dict(reversed(i) for i in mapping.items()))

    def set_abi_cc(self, abi, cc_cls):
        """
        Set the default calling convention for an abi

        :param abi:     The name of the abi
        :param cc_cls:  A SimCC _class_, not an instance, that should be used for syscalls using the abi
        """
        self.default_cc_mapping[abi] = cc_cls

    def set_prototype(self, abi: str, name: str, proto: SimTypeFunction) -> None:  # pylint: disable=arguments-differ
        """
        Set the prototype of a function in the form of a SimTypeFunction containing argument and return types

        :param abi:     ABI of the syscall.
        :param name:    The name of the syscall as a string
        :param proto:   The prototype of the syscall as a SimTypeFunction
        """
        self.syscall_prototypes[abi][name] = proto

    def set_prototypes(self, abi: str, protos: Dict[str,SimTypeFunction]) -> None:  # pylint: disable=arguments-differ
        """
        Set the prototypes of many syscalls.

        :param abi:     ABI of the syscalls.
        :param protos:  Dictionary mapping syscall names to SimTypeFunction objects
        """
        self.syscall_prototypes[abi].update(protos)

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
            proc.cc = cc
        # a bit of a hack.
        name = proc.display_name
        if self.syscall_prototypes[abi].get(name, None) is not None:
            proc.prototype = self.syscall_prototypes[abi][name].with_arch(arch)

    # pylint: disable=arguments-differ
    def get(self, number, arch, abi_list=()):
        """
        The get() function for SimSyscallLibrary looks a little different from its original version.

        Instead of providing a name, you provide a number, and you additionally provide a list of abi names that are
        applicable. The first abi for which the number is present in the mapping will be chosen. This allows for the
        easy abstractions of architectures like ARM or MIPS linux for which there are many ABIs that can be used at any
        time by using syscall numbers from various ranges. If no abi knows about the number, the stub procedure with
        the name "sys_%d" will be used.

        :param number:      The syscall number
        :param arch:        The architecture being worked with, as either a string name or an archinfo.Arch
        :param abi_list:    A list of ABI names that could be used
        :return:            A SimProcedure representing the implementation of the given syscall, or a stub if no
                            implementation is available
        """
        name, arch, abi = self._canonicalize(number, arch, abi_list)
        proc = super().get(name, arch)
        proc.is_syscall = True
        self._apply_numerical_metadata(proc, number, arch, abi)
        return proc

    def get_stub(self, number, arch, abi_list=()):
        """
        Pretty much the intersection of SimLibrary.get_stub() and SimSyscallLibrary.get().

        :param number:      The syscall number
        :param arch:        The architecture being worked with, as either a string name or an archinfo.Arch
        :param abi_list:    A list of ABI names that could be used
        :return:            A SimProcedure representing a plausable stub that could model the syscall
        """
        name, arch, abi = self._canonicalize(number, arch, abi_list)
        proc = super().get_stub(name, arch)
        self._apply_numerical_metadata(proc, number, arch, abi)
        l.debug("unsupported syscall: %s", number)
        return proc

    def get_prototype(self, abi: str, name: str, arch=None) -> Optional[SimTypeFunction]:
        """
        Get a prototype of the given syscall name and its ABI, optionally specialize the prototype to a given
        architecture.

        :param abi:     ABI of the prototype to get.
        :param name:    Name of the syscall.
        :param arch:    The architecture to specialize to.
        :return:        Prototype of the syscall, or None if the prototype does not exist.
        """
        if abi not in self.syscall_prototypes:
            return None
        proto = self.syscall_prototypes[abi].get(name, None)
        if proto is None:
            return None
        return proto.with_arch(arch=arch)

    def has_metadata(self, number, arch, abi_list=()):
        """
        Pretty much the intersection of SimLibrary.has_metadata() and SimSyscallLibrary.get().

        :param number:      The syscall number
        :param arch:        The architecture being worked with, as either a string name or an archinfo.Arch
        :param abi_list:    A list of ABI names that could be used
        :return:            A bool of whether or not any implementation or metadata is known about the given syscall
        """
        name, _, _ = self._canonicalize(number, arch, abi_list)
        return super().has_metadata(name)

    def has_implementation(self, number, arch, abi_list=()):
        """
        Pretty much the intersection of SimLibrary.has_implementation() and SimSyscallLibrary.get().

        :param number:      The syscall number
        :param arch:        The architecture being worked with, as either a string name or an archinfo.Arch
        :param abi_list:    A list of ABI names that could be used
        :return:            A bool of whether or not an implementation of the syscall is available
        """
        name, _, _ = self._canonicalize(number, arch, abi_list)
        return super().has_implementation(name)

    def has_prototype(self, abi: str, name: str) -> bool:
        """
        Check if a function has a prototype associated with it. Demangle the function name if it is a mangled C++ name.

        :param abi:         Name of the ABI.
        :param name:        The syscall name.
        :return:            bool
        """
        if abi not in self.syscall_prototypes:
            return False
        return name in self.syscall_prototypes[abi]


#
# Autoloading
#

# By default we only load common API definitions (as defined in COMMON_LIBRARIES). For loading more definitions, the
# following logic is followed:
# - We will load all Windows APIs them if the loaded binary is a Windows binary, or when load_win32api_definitions() is
#   called.
# - We will load all APIs when load_all_definitions() is called.

_DEFINITIONS_BASEDIR = os.path.dirname(os.path.realpath(__file__))


def load_win32api_definitions():
    if once('load_win32api_definitions'):
        for _ in autoimport.auto_import_modules('angr.procedures.definitions', _DEFINITIONS_BASEDIR,
                                                filter_func=lambda module_name: module_name.startswith("win32_"),
                                                ):
            pass


def load_all_definitions():
    if once('load_all_definitions'):
        for _ in autoimport.auto_import_modules('angr.procedures.definitions', _DEFINITIONS_BASEDIR):
            pass


COMMON_LIBRARIES = {
    # CGC
    'cgc',
    # (mostly) Linux
    'glibc',
    'gnulib',  # really just for .o files in coreutils
    'libstdcpp',
    'linux_kernel',
    'linux_loader',
    # Windows
    'msvcr',
}


for _ in autoimport.auto_import_modules('angr.procedures.definitions', _DEFINITIONS_BASEDIR,
                                        filter_func=lambda module_name: module_name in COMMON_LIBRARIES,
                                        ):
    pass
