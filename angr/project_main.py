#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import simuvex    # pylint: disable=F0401
import cle
from .project_base import ProjectBase
import logging
import claripy
import md5
import struct

claripy.init_standalone()
l = logging.getLogger("angr.project")



class Project(ProjectBase):    # pylint: disable=R0904,
    """ This is the main class of the Angr module
        The code in this file focuses on the usage of SimProcedures.
        Low level functions of Project are defined in ProjectBase.
    """

    def __init__(self, filename, use_sim_procedures=None,
                 exclude_sim_procedure=lambda x: False, arch=None,
                 exclude_sim_procedures=(), default_analysis_mode=None,
                 force_ida=None, ida_main=None, load_libs=None, skip_libs=None,
                 except_thumb_mismatch=False):
        """
        This constructs a Project_cle object.

        Arguments:
            @param filename: path to the binary object to analyse
            @param arch: optional target architecture (auto-detected otherwise)
            @param exclude_sim_procedures: a list of functions to *not* wrap with
            sim_procedures

            NOTE:
                @arch is now optional, and overrides Cle's guess
                @load_libs is now obsolete
                @binary_base_addr is now obsolete
                @allow pybfd is now obsolete
                @allow_r2 is now obsolete
                """

        if (not default_analysis_mode):
            default_analysis_mode = 'static'

        self.force_ida = force_ida
        self.irsb_cache = {}
        self.binaries = {}
        self.surveyors = []
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.default_analysis_mode = default_analysis_mode
        self.exclude_sim_procedures = exclude_sim_procedures
        self.exclude_all_sim_procedures = exclude_sim_procedures
        self.except_thumb_mismatch=except_thumb_mismatch

        self.__cfg = None
        self.__cdg = None
        self.__ddg = None

        # This is a map from IAT addr to (SimProcedure class name, kwargs_
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # Ld guesses the architecture, loads the binary, its dependencies and
        # performs relocations.
        ld = cle.Ld(filename, force_ida=force_ida, load_libs=load_libs, skip_libs=skip_libs)
        self.ld = ld
        self.main_binary = ld.main_bin

        if arch:
            l.debug("Warning: you are manually specifying the architecture")
            #self.arch = simuvex.Architectures[arch]()
        else:
            # Ld uses BFD style arch names, we need to convert it to simuvex's
            # arch names
            arch = ld.main_bin.simarch

        if arch is None:
            raise Exception("Architecture is None, this should not happen")
        elif isinstance(arch, simuvex.SimArch):
            self.arch = arch
        else:
            self.arch = simuvex.Architectures[arch]()

        self.min_addr = ld.min_addr()
        self.max_addr = ld.max_addr()
        self.entry = ld.main_bin.entry_point


        if use_sim_procedures == True:
            self.use_sim_procedures()

            # We need to resync memory as simprocedures have been set at the
            # level of each IDA's instance
            if self.force_ida == True:
                self.ld.ida_sync_mem()

        self.vexer = VEXer(ld.memory, self.arch, use_cache=self.arch.cache_irsb)

    def exclude_sim_procedure(self, f):
        return f in self.exclude_sim_procedures

    def __find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex
        """
        simlibs = []

        libs = [os.path.basename(o) for o in self.ld.dependencies.keys()]
        for lib_name in libs:
            # Hack that should go somewhere else:
            if lib_name == 'libc.so.0':
                lib_name = 'libc.so.6'

            if not (lib_name in simuvex.procedures.SimProcedures):
                l.debug("There are no simprocedures for library %s :(" % lib_name)
            else:
                simlibs.append(lib_name)

        return simlibs

    def use_sim_procedures(self):
        """ Use simprocedures where we can """

        libs = self.__find_sim_libraries()

        unresolved = []

        for i in self.main_binary.imports.keys():
            unresolved.append(i)

        l.debug("[Resolved [R] SimProcedures]")
        for i in self.main_binary.imports.keys():
            if self.exclude_sim_procedure(i):
                l.debug("%s: SimProcedure EXCLUDED", i)
                continue

            for lib in libs:
                simfun = simuvex.procedures.SimProcedures[lib]
                if i not in simfun.keys():
                    continue
                l.debug("[R] %s:", i)
                l.debug("\t -> matching SimProcedure in %s :)", lib)
                self.set_sim_procedure(self.main_binary, lib, i,
                                           simfun[i], None)
                unresolved.remove(i)

        # What's left in imp is unresolved.
        l.debug("[Unresolved [U] SimProcedures]: using ReturnUnconstrained instead")

        for i in unresolved:
            l.debug("[U] %s", i)
            self.set_sim_procedure(self.main_binary, "stubs", i,
                                   simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                                   None)

    def update_jmpslot_with_simprocedure(self, func_name, pseudo_addr, binary):
        """ Update a jump slot (GOT address referred to by a PLT slot) with the
        address of a simprocedure """
        self.ld.override_got_entry(func_name, pseudo_addr, binary)

    def add_custom_sim_procedure(self, address, sim_proc, kwargs):
        '''
        Link a SimProcedure class to a specified address.
        '''
        if address in self.sim_procedures:
            l.warning("Address 0x%08x is already in SimProcedure dict.", address)
            return
        if kwargs is None: kwargs = {}
        self.sim_procedures[address] = (sim_proc, kwargs)

    def is_sim_procedure(self, hashed_addr):
        return hashed_addr in self.sim_procedures

    def get_pseudo_addr_for_sim_procedure(self, s_proc):
        for addr, tpl in self.sim_procedures.items():
            simproc_class, _ = tpl
            if isinstance(s_proc, simproc_class):
                return addr
        return None

    def set_sim_procedure(self, binary, lib, func_name, sim_proc, kwargs):
        """
         This method differs from Project_ida's one with same name

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
        if (pseudo_addr in self.sim_procedures) and \
                            (self.sim_procedures[pseudo_addr][0] != sim_proc):
            l.warning("Address 0x%08x is already in SimProcedure dict.", pseudo_addr)
            return

        self.sim_procedures[pseudo_addr] = (sim_proc, kwargs)
        l.debug("\t -> setting SimProcedure with pseudo_addr 0x%x...", pseudo_addr)

        if self.force_ida == True:
            binary.resolve_import_with(func_name, pseudo_addr)
            #binary.resolve_import_dirty(func_name, pseudo_addr)
        else:
            self.update_jmpslot_with_simprocedure(func_name, pseudo_addr, binary)



from .errors import AngrMemoryError, AngrExitError
from .vexer import VEXer
from .cfg import CFG
