#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import simuvex    # pylint: disable=F0401
import cPickle as pickle
import struct
import md5

import logging
l = logging.getLogger("angr.project")

granularity = 0x1000000

class Project(object):    # pylint: disable=R0904,
    """ This is the main class of the Angr module """

    def __init__(self, filename, arch=None, binary_base_addr=None,
                 load_libs=None, resolve_imports=None,
                 use_sim_procedures=None, exclude_sim_procedures=(),
                 exclude_sim_procedure=lambda x: False,
                 default_analysis_mode=None, allow_pybfd=True,
                 allow_r2=True):
        """
        This constructs a Project object.

        Arguments:
            @param filename: path to the binary object to analyse
            @param arch: target architecture (defaults to "AMD64")
            @param binary_base_addr: binary base address
            @param load_libs: attempt to load libraries externally linked to
                     the program (e.g. libc6). Note that a copy of all the shared
                     library objects should be placed in the same directory as the
                     target binary file beforehands.
            @param exclude_sim_procedures: a list of functions to *not* wrap with
                    sim_procedures
        """

        if arch is None:
            arch = simuvex.SimAMD64()
        elif type(arch) is str:
            arch = simuvex.Architectures[arch]()
        elif not isinstance(arch, simuvex.SimArch):
            raise Exception("invalid arch argument to Project")

        load_libs = True if load_libs is None else load_libs
        resolve_imports = True if resolve_imports is None else resolve_imports
        use_sim_procedures = False if use_sim_procedures is None else use_sim_procedures
        default_analysis_mode = 'static' if default_analysis_mode is None else default_analysis_mode

        self.irsb_cache = { }
        self.binaries = {}
        self.arch = arch
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.default_analysis_mode = default_analysis_mode
        self.exclude_sim_procedure = lambda x: exclude_sim_procedure(x) or x in exclude_sim_procedures

        # This is a map from IAT addr to (SimProcedure class name, kwargs_
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)
        self.binaries[self.filename] = Binary(filename, arch, self, \
                                            base_addr=binary_base_addr, \
                                            allow_pybfd=allow_pybfd, allow_r2=allow_r2)
        self.main_binary = self.binaries[self.filename]

        self.min_addr = self.binaries[self.filename].min_addr()
        self.max_addr = self.binaries[self.filename].max_addr()
        self.entry = self.binaries[self.filename].entry()

        if load_libs:
            self.load_libs()
            if resolve_imports:
                self.resolve_imports_from_libs()

        if use_sim_procedures:
            self.resolve_imports_using_sim_procedures()

        self.mem = MemoryDict(self.binaries, 'mem')
        # TODO: arch-dependent pages
        self.perm = MemoryDict(self.binaries, 'perm', granularity=0x1000)

        self.mem.pull()
        self.vexer = VEXer(self.mem, self.arch, use_cache=self.arch.cache_irsb)

    def save_mem(self):
        """ Save memory to file (mem.p)"""
        self.mem.pull()
        self.perm.pull()

        memfile = self.dirname + "/mem.p"
        pickle.dump((self.mem, self.perm), open(memfile, "w"))

    def load_mem(self):
        """ Load memory from file (mem.p)"""
        memfile = self.dirname + "/mem.p"
        self.mem, self.perm = pickle.load(open(memfile))

    def find_delta(self, lib):
        """
        Find relocation address of library
        @argument lib: the library
        """

        min_addr_bin = lib.min_addr()
        max_addr_bin = lib.max_addr()

        l.debug("Calculating rebasing address of %s with address range (0x%x, 0x%x)", lib, min_addr_bin, max_addr_bin)

        # to avoid bugs, let's just relocate after for now, with a granularity
        # between them
        start_offset = min_addr_bin % granularity
        new_start_bin = granularity * ((self.max_addr + granularity) /
                                       granularity) + start_offset
        l.debug("Binary %s will be allocated to 0x%x", lib, new_start_bin)
        delta = new_start_bin - min_addr_bin
        return delta

    def next_base(self):
        base = self.max_addr + (granularity - self.max_addr % granularity)
        return base

    def load_libs(self):
        """ Load all the dynamically linked libraries of the binary"""
        remaining_libs = set(self.binaries[self.filename].get_lib_names())
        if(len(remaining_libs) == 0):
            l.debug("Warning: load_libs found 0 libs")

        done_libs = set()

        # load all the libs
        while len(remaining_libs) > 0:
            lib = remaining_libs.pop()
            lib_path = os.path.join(self.dirname, lib)

            if lib not in done_libs and os.path.exists(lib_path):
                done_libs.add(lib)

                # load new bin
                new_base_addr = self.next_base()
                l.debug("Loading lib %s at base address 0x%08x", lib, new_base_addr)
                new_lib = Binary(lib_path, self.arch, self, base_addr=new_base_addr)
                self.binaries[lib] = new_lib

                # update min and max addresses
                self.min_addr = min(self.min_addr, new_lib.min_addr())
                self.max_addr = max(self.max_addr, new_lib.max_addr())

                remaining_libs.update(new_lib.get_lib_names())

    def resolve_imports_from_libs(self):
        """ Resolves binary's imports from the loaded libraries"""
        for b in self.binaries.values():
            resolved = {}

            for lib_name in b.get_lib_names():
                if lib_name not in self.binaries:
                    l.warning("Lib %s not loaded. Can't resolve exports from this library.", lib_name)
                    continue

                lib = self.binaries[lib_name]

                for export, export_type in lib.get_exports():
                    try:
                        addr = lib.get_symbol_addr(export)
                        if addr == None:
                            l.warning("Got None for export %s[%s] from bin %s", export, export_type, lib_name, exc_info=True)
                        else:
                            resolved[export] = lib.get_symbol_addr(export)
                    except Exception:
                        l.warning("Unable to get address of export %s[%s] from bin %s. This happens sometimes.", export, export_type, lib_name, exc_info=True)

            imports = b.get_imports()
            if imports is not None:
                for imp, imp_addr in b.get_imports():
                    if imp in resolved:
                        l.debug("Resolving import %s of bin %s to 0x08%x", imp, b.filename, resolved[imp])
                        try:
                            b.resolve_import(imp, resolved[imp])
                        except Exception:
                            l.warning("Mismatch between IDA info and ELF info. Symbols %s in binary %s", imp, b.filename)
                    else:
                        l.warning("Unable to resolve import %s of binary %s", imp, b.filename)
            else:
                imports = b.get_imports_from_ida()
                for imp in imports:
                    if imp.name in resolved:
                        l.debug("Resolving import %s of binary %s to 0x%08x", imp, b.filename, resolved[imp.name])
                        try:
                            b.resolve_import(imp.name, resolved[imp.name])
                        except Exception:
                            l.warning("Mismatch between IDA info and ELF info. Symbols %s in bin %s", imp, b.filename)
                    else:
                        l.warning("Unable to resolve import %s of binary %s", imp.name, b.filename)
                        if self.arch.name == "MIPS32":
                            l.warning("Give it a Retn stub instead, eax = 0x%08x.", imp.ea)
                            # TODO: Generate a new address, and update it at that place
                            self.set_sim_procedure(b, imp.module_name, imp.name, \
                                                   simuvex.SimProcedures["stubs"]["ReturnUnconstrained"], \
                                                   None)

    def resolve_imports_using_sim_procedures(self):
        """
        Resolves binary's imports using sym_procedures instead of the actual
        libraries.
        Now it only supports the main binary!
        """
        binary_name = self.filename
        binary = self.binaries[binary_name]
        for lib_name in binary.get_lib_names():
            if lib_name == 'libc.so.0':
                lib_name = 'libc.so.6'

            if lib_name in simuvex.procedures.SimProcedures:
                functions = simuvex.procedures.SimProcedures[lib_name]
                imports = binary.get_imports()
                if imports is not None:
                    for imp, _ in imports:
                        l.debug("(Import) looking for SimProcedure %s in %s", imp, lib_name)
                        if self.exclude_sim_procedure(imp):
                            l.debug("... excluded!")
                            continue

                        if imp in functions:
                            l.debug("... sim_procedure %s found!", imp)
                            self.set_sim_procedure(binary, lib_name, imp,
                                                functions[imp], None)
                else:
                    imports = binary.get_imports_from_ida()
                    for imp in imports:
                        l.debug("Looking for SimProcedure %s in %s", imp.name, lib_name)
                        if self.exclude_sim_procedure(imp.name):
                            l.debug("... excluded!")
                            continue

                        if imp in functions:
                            l.debug("... SimProcedure %s is found!", imp.name)
                            self.set_sim_procedure(binary, lib_name, imp.name,
                                                functions[imp.name], None)

    def functions(self):
        functions = {}
        for b in self.binaries.values():
            functions.update(b.functions(mem=self.mem))
        return functions

    def binary_by_addr(self, addr):
        for b in self.binaries.itervalues():
            if b.min_addr() <= addr <= b.max_addr():
                return b

    def initial_state(self, options=None, mode=None):
        """Creates an initial state, with stack and everything."""
        if mode is None and options is None:
            mode = self.default_analysis_mode
        s = simuvex.SimState(memory_backer=self.mem, arch=self.arch, mode=mode, options=options).copy()

        # Initialize the stack pointer
        if s.arch.name == "AMD64":
            s.store_reg(176, 1, 8)
            s.store_reg(s.arch.sp_offset, 0xfffffffffff0000, 8)
        elif s.arch.name == "X86":
            s.store_reg(s.arch.sp_offset, 0x7fff0000, 4)
        elif s.arch.name == "ARM":
            s.store_reg(s.arch.sp_offset, 0xffff0000, 4)

            # the freaking THUMB state
            s.store_reg(0x188, 0x00000000, 4)
        elif s.arch.name == "PPC32":
            # TODO: Is this correct?
            s.store_reg(s.arch.sp_offset, 0xffff0000, 4)
        elif s.arch.name == "MIPS32":
            # TODO: Is this correct?
            s.store_reg(s.arch.sp_offset, 0xffff0000, 4)
        else:
            raise Exception("Architecture %s is not supported." % s.arch.name)
        return s

    def initial_exit(self, mode=None, options=None):
        """Creates a SimExit to the entry point."""
        return self.exit_to(self.entry, mode=mode, options=options)

    def exit_to(self, addr, state=None, mode=None, options=None, jumpkind=None):
        """Creates a SimExit to the specified address."""
        if state is None:
            state = self.initial_state(mode=mode, options=options)
        return simuvex.SimExit(addr=addr, state=state, jumpkind=jumpkind)

    def block(self, addr, max_size=None, num_inst=None, traceflags=0):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        thumb = False
        if self.arch.name == "ARM":
            if self.binary_by_addr(addr) is None:
                raise AngrMemoryError("No IDA to check thumb mode at 0x%x." % addr)

            if self.binary_by_addr(addr).ida.idc.GetReg(addr, "T") == 1:
                thumb = True

        return self.vexer.block(addr, max_size=max_size, num_inst=num_inst, traceflags=traceflags, thumb=thumb)

    def sim_block(self, where, max_size=None, num_inst=None, stmt_whitelist=None, last_stmt=None):
        """
        Returns a simuvex block starting at SimExit 'where'

        Optional params:

        @param where: the exit to start the analysis at
        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param state: the initial state. Fully unconstrained if None

        """
        irsb = self.block(where.concretize(), max_size, num_inst)
        return simuvex.SimIRSB(where.state, irsb, addr=where.concretize(), whitelist=stmt_whitelist, last_stmt=last_stmt)

    def sim_run(self, where, max_size=400, num_inst=None, stmt_whitelist=None, last_stmt=None):
        """
        Returns a simuvex SimRun object (supporting refs() and
        exits()), automatically choosing whether to create a SimIRSB or
        a SimProcedure.

        Parameters:
        @param where : the exit to analyze
        @param max_size : the maximum size of the block, in bytes
        @param num_inst : the maximum number of instructions
        @param state : the initial state. Fully unconstrained if None
        """

        if where.is_error:
            raise AngrExitError("Provided exit of jumpkind %s is in an error state.", where.jumpkind)

        addr = where.concretize()
        state = where.state

        if addr % state.arch.instruction_alignment != 0:
            raise AngrExitError("Address 0x%x does not align to alignment %d for architecture %s." % (addr, state.arch.instruction_alignment, state.arch.name))

        if where.is_syscall:
            l.debug("Invoking system call handler (originally at 0x%x)", addr)
            return simuvex.SimProcedures['syscalls']['handler'](state, addr=addr)
        if self.is_sim_procedure(addr):
            sim_proc_class, kwargs = self.sim_procedures[addr]
            l.debug("Creating SimProcedure %s (originally at 0x%x)", sim_proc_class.__name__, addr)
            return sim_proc_class(state, addr=addr, **kwargs)
        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            return self.sim_block(where, max_size=max_size, num_inst=num_inst, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)

    def add_custom_sim_procedure(self, address, sim_proc, kwargs):
        '''
        Link a SimProcedure class to a specified address.
        '''
        if address in self.sim_procedures:
            l.warning("Address 0x%08x is already in SimProcedure dict.", address)
            return
        if kwargs is None: kwargs = {}
        self.sim_procedures[address] = (sim_proc, kwargs)

    def set_sim_procedure(self, binary, lib, func_name, sim_proc, kwargs):
        """
         Generate a hashed address for this function, which is used for
         indexing the abstract function later.
         This is so hackish, but thanks to the fucking constraints, we have no
         better way to handle this
        """
        m = md5.md5()
        m.update(lib + "_" + func_name)
        # TODO: update addr length according to different system arch
        hashed_bytes = m.digest()[:self.arch.bits/8]
        pseudo_addr = (struct.unpack(self.arch.struct_fmt, hashed_bytes)[0] / 4) * 4

        # Put it in our dict
        if kwargs is None: kwargs = {}
        if pseudo_addr in self.sim_procedures and self.sim_procedures[pseudo_addr][0] != sim_proc:
            l.warning("Address 0x%08x is already in SimProcedure dict.", pseudo_addr)
            return
        self.sim_procedures[pseudo_addr] = (sim_proc, kwargs)
        l.debug("Setting SimProcedure %s with psuedo_addr 0x%x...", func_name,
                pseudo_addr)

        # Update all the stubs for the function
        binary.resolve_import(func_name, pseudo_addr)

    def is_sim_procedure(self, hashed_addr):
        return hashed_addr in self.sim_procedures

    def get_pseudo_addr_for_sim_procedure(self, s_proc):
        for addr, tpl in self.sim_procedures.items():
            simproc_class, _ = tpl
            if isinstance(s_proc, simproc_class):
                return addr
        return None

    def construct_cfg(self, avoid_runs=[]):
        c = CFG()
        c.construct(self.main_binary, self, avoid_runs=avoid_runs)
        return c

from .binary import Binary
from .memory_dict import MemoryDict
from .errors import AngrMemoryError, AngrExitError
from .vexer import VEXer
from .cfg import CFG
