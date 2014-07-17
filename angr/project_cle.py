#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import simuvex    # pylint: disable=F0401
import struct
import md5
import cle
from .project_abs import AbsProject
import logging
l = logging.getLogger("angr.project")


class Project_cle(AbsProject):    # pylint: disable=R0904,
    """ This is the main class of the Angr module """

    def __init__(self, filename, use_sim_procedures=None, arch=None,
                 exclude_sim_procedures=(), default_analysis_mode=None):
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

        self.irsb_cache = {}
        self.binaries = {}
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.default_analysis_mode = default_analysis_mode
        self.exclude_sim_procedures = exclude_sim_procedures

        # This is a map from IAT addr to (SimProcedure class name, kwargs_
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # Ld guesses the architecture, loads the binary, its dependencies and
        # performs relocations.
        ld = cle.Ld(filename)
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
        self.arch = simuvex.Architectures[arch]()

        self.min_addr = ld.min_addr()
        self.max_addr = ld.max_addr()
        self.entry = ld.main_bin.entry_point

        if use_sim_procedures:
            self.use_sim_procedures()

        self.mem = ld.memory
        self.vexer = VEXer(self.mem, self.arch, use_cache=self.arch.cache_irsb)

    def use_sim_procedures(self):
        """ Use simprocedures where we can """
        # Look for implemented libraries
        libs = self.__find_sim_libraries()
        for lib in libs:
            # Look for implemented functions
            fun = self.__find_sim_functions(lib)

            # Get the dictionary {function => symprocedure} for lib
            simfun = simuvex.procedures.SimProcedures[lib]

            # Replace the functions with simprocedures
            for f in fun:
                self.set_sim_procedure(self.main_binary, lib, f,
                                       simfun[f], None)

    def __find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex"""
        simlibs = []

        for lib_name in self.main_binary.deps:
            # Hack that should go somewhere else:
            if lib_name == 'libc.so.0':
                lib_name = 'libc.so.6'

            if not (lib_name in simuvex.procedures.SimProcedures):
                l.debug("There are no simprocedures for library %s :(" % lib_name)
            else:
                simlibs.append(lib_name)

        return simlibs

    def __find_sim_functions(self, lib_name):
        """
        For a given library, finds the set of functions that we can replace with
        simuvex simprocedures
        """
        simfunc = []

        functions = simuvex.procedures.SimProcedures[lib_name]
        imports = self.main_binary.get_imports()

        for imp, addr in imports.iteritems():
            l.debug("(Import) looking for SimProcedure %s in %s", imp,
                    lib_name)

            if imp in self.exclude_sim_procedures:
                l.debug("... excluded!")
                continue

            if imp in functions:
                l.debug("... sim_procedure %s found!", imp)
                simfunc.append(imp)

        return simfunc

    def binary_by_addr(self, addr):
        """ This method differs from Project_ida's one with same name"""
        return self.ld.addr_belongs_to_object(addr)

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
        l.debug("Setting SimProcedure %s with psuedo_addr 0x%x...", func_name,
                pseudo_addr)

        # Update all the stubs for the function
        #binary.resolve_import(func_name, pseudo_addr)
        cle.Ld.override_got_entry(func_name, pseudo_addr, binary)


from .errors import AngrMemoryError, AngrExitError
from .vexer import VEXer
from .cfg import CFG
