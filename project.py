#!/usr/bin/env python


# pylint: disable=W0201
# pylint: disable=W0703

import os
import pyvex  # pylint: disable=F0401
import simuvex    # pylint: disable=F0401
import cPickle as pickle
import struct
import md5

from .binary import Binary
from .memory_dict import MemoryDict
from .errors import AngrMemoryError

import logging
l = logging.getLogger("angr.project")

granularity = 0x1000000

class ExploreResults:
    def __init__(self):
        self.incomplete = [ ]
        self.found = [ ]
        self.avoided = [ ]
        self.deviating = [ ]
        self.discarded = [ ]
        self.looping = [ ]
        self.deadended = [ ]
        self.instruction_counts = { }

    def __str__(self):
        return "<ExploreResult with %d found, %d avoided, %d incomplete, %d deviating, %d discarded, %d deadended, %d looping>" % (len(self.found), len(self.avoided), len(self.incomplete), len(self.deviating), len(self.discarded), len(self.deadended), len(self.looping))

class Project(object):    # pylint: disable=R0904,
    """ This is the main class of the Angr module """

    def __init__(self, filename, arch=None, binary_base_addr=None,
                 load_libs=None, resolve_imports=None,
                 use_sim_procedures=None, exclude_sim_procedures=(),
                 default_analysis_mode=None):
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

        arch = "AMD64" if arch is None else arch
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
        self.exclude_sim_procedures = exclude_sim_procedures

        l.info("Loading binary %s" % self.filename)
        l.debug("... from directory: %s", self.dirname)
        self.binaries[self.filename] = Binary(filename, arch, base_addr=binary_base_addr)

        self.min_addr = self.binaries[self.filename].min_addr()
        self.max_addr = self.binaries[self.filename].max_addr()
        self.entry = self.binaries[self.filename].entry()

        # This is a map from IAT addr to SimProcedure
        self.sim_procedures = {}

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

        l.debug("Calculating rebasing address of %s with address range (0x%x, 0x%x)" % (lib, min_addr_bin, max_addr_bin))

        # to avoid bugs, let's just relocate after for now, with a granularity
        # between them
        start_offset = min_addr_bin % granularity
        new_start_bin = granularity * ((self.max_addr + granularity) /
                                       granularity) + start_offset
        l.debug("Binary %s will be allocated to 0x%x" % (lib, new_start_bin))
        delta = new_start_bin - min_addr_bin
        return delta

    def next_base(self):
        base = self.max_addr + (granularity - self.max_addr % granularity)
        return base

    def load_libs(self):
        """ Load all the dynamically linked libraries of the binary"""
        remaining_libs = set(self.binaries[self.filename].get_lib_names())
        done_libs = set()

        # load all the libs
        while len(remaining_libs) > 0:
            lib = remaining_libs.pop()
            lib_path = os.path.join(self.dirname, lib)

            if lib not in done_libs and os.path.exists(lib_path):
                l.debug("Loading lib %s" % lib)
                done_libs.add(lib)

                # load new bin
                new_lib = Binary(lib_path, self.arch, base_addr=self.next_base())
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
                    l.warning("Lib %s not loaded. Can't resolve exports from this library." % lib_name)
                    continue

                lib = self.binaries[lib_name]

                for export, export_type in lib.get_exports():
                    try:
                        addr = lib.get_symbol_addr(export)
                        if addr == None:
                            l.warning("Got None for export %s[%s] from bin %s" % (export, export_type, lib_name), exc_info=True)
                        else:
                            resolved[export] = lib.get_symbol_addr(export)
                    except Exception:
                        l.warning("Unable to get address of export %s[%s] from bin %s. This happens sometimes." % (export, export_type, lib_name), exc_info=True)

            for imp, _ in b.get_imports():
                if imp in resolved:
                    l.debug("Resolving import %s of bin %s to 0x%x" % (imp, b.filename, resolved[imp]))
                    try:
                        b.resolve_import(imp, resolved[imp])
                    except Exception:
                        l.warning("Mismatch between IDA info and ELF info. Symbols %s in bin %s" % (imp, b.filename))
                else:
                    l.warning("Unable to resolve import %s of bin %s"
                              % (imp, b.filename))

    def resolve_imports_using_sim_procedures(self):
        """
        Resolves binary's imports using sym_procedures instead of the actual
        libraries.
        Now it only supports the main binary!
        """
        binary_name = self.filename
        binary = self.binaries[binary_name]
        for lib_name in binary.get_lib_names():
            l.debug("AbstractProc: lib_name: %s", lib_name)
            if lib_name in simuvex.procedures.SimProcedures:
                functions = simuvex.procedures.SimProcedures[lib_name]
                # l.debug(functions)
                for imp, _ in binary.get_imports():
                    l.debug("Checking proecedure import %s", imp)
                    if imp in self.exclude_sim_procedures:
                        l.debug("... excluded!")
                        continue

                    if imp in functions:
                        l.debug("... sim_procedure %s found!", imp)
                        self.set_sim_procedure(binary, lib_name, imp,
                                               functions[imp])

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
        s = simuvex.SimState(memory_backer=self.mem, arch=self.arch, mode=mode, options=options).copy_after()

        # Initialize the stack pointer
        if s.arch.name == "AMD64":
            s.store_reg(s.arch.sp_offset, 0xfffffffffff0000, 8)
        elif s.arch.name == "ARM":
            s.store_reg(s.arch.sp_offset, 0xffff0000, 4)
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

    def exit_to(self, addr, state=None, mode=None, options=None):
        """Creates a SimExit to the specified address."""
        if state is None:
            state = self.initial_state(mode=mode, options=options)
        return simuvex.SimExit(addr=addr, state=state)

    def block(self, addr, max_size=None, num_inst=None, traceflags=0):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        max_size = 400 if max_size is None else max_size
        num_inst = 99 if num_inst is None else num_inst

        # TODO: FIXME: figure out what to do if we're about to exhaust the memory
        # (we can probably figure out how many instructions we have left by talking to IDA)

        # TODO: remove this ugly horrid hack
        try:
            buff = self.mem[addr:addr + max_size]
        except KeyError as e:
            buff = self.mem[addr:e.message]

        # deal with thumb mode in ARM, sending an odd address and an offset
        # into the string
        byte_offset = 0
        if self.arch == "ARM" and self.binary_by_addr(
                addr).ida.idc.GetReg(addr, "T") == 1:
            addr += 1
            byte_offset = 1

        if not buff:
            raise AngrMemoryError("No bytes in memory for block starting at 0x%x." % addr)

        l.debug("Creating pyvex.IRSB of arch %s at 0x%x", self.arch, addr)
        vex_arch = "VexArch" + self.arch

        cache_key = (buff, addr, num_inst, vex_arch, byte_offset, traceflags)
        if cache_key in self.irsb_cache:
            return self.irsb_cache[cache_key]

        if num_inst:
            block = pyvex.IRSB(bytes=buff, mem_addr=addr, num_inst=num_inst, arch=vex_arch, bytes_offset=byte_offset, traceflags=traceflags)
        else:
            block = pyvex.IRSB(bytes=buff, mem_addr=addr, arch=vex_arch, bytes_offset=byte_offset, traceflags=traceflags)

        self.irsb_cache[cache_key] = block
        return block

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
        return simuvex.SimIRSB(where.state, irsb, whitelist=stmt_whitelist, last_stmt=last_stmt)

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

        addr = where.concretize()
        state = where.state

        if self.is_sim_procedure(addr):
            sim_proc = self.sim_procedures[addr](state, addr=addr)

            l.debug("Creating SimProcedure %s (originally at 0x%x)", sim_proc.__class__.__name__, addr)
            return sim_proc
        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            return self.sim_block(where, max_size=max_size, num_inst=num_inst, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)

    def add_custom_sim_procedure(self, address, sim_proc):
        '''
        Link a SimProcedure class to a specified address.
        '''
        self.sim_procedures[address] = sim_proc

    def set_sim_procedure(self, binary, lib, func_name, sim_proc):
        """
         Generate a hashed address for this function, which is used for
         indexing the abstract function later.
         This is so hackish, but thanks to the fucking constraints, we have no
         better way to handle this
        """
        m = md5.md5()
        m.update(lib + "_" + func_name)
        # TODO: update addr length according to different system arch
        hashed_bytes = m.digest()[:binary.bits/8]
        pseudo_addr = (struct.unpack(binary.struct_format, hashed_bytes)[0] / 4) * 4

        # Put it in our dict
        self.sim_procedures[pseudo_addr] = sim_proc
        l.debug("Setting SimProcedure %s with psuedo_addr 0x%x...", func_name,
                pseudo_addr)

        # Update all the stubs for the function
        binary.resolve_import(func_name, pseudo_addr)

    def is_sim_procedure(self, hashed_addr):
        return hashed_addr in self.sim_procedures

    def get_pseudo_addr_for_sim_procedure(self, s_proc):
        for addr, class_ in self.sim_procedures.items():
            if isinstance(s_proc, class_):
                return addr
        return None
