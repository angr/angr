#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import simuvex    # pylint: disable=F0401
import cle
from .project_abs import AbsProject
import logging
import claripy
import pdb

claripy.init_standalone()
l = logging.getLogger("angr.project")


class Project(AbsProject):    # pylint: disable=R0904,
    """ This is the main class of the Angr module """

    def __init__(self, filename, use_sim_procedures=None,
                 exclude_sim_procedure=lambda x: False, arch=None,
                 exclude_sim_procedures=(), default_analysis_mode=None,
                 force_ida=None, ida_main=None, load_libs=None):
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

        # This is a map from IAT addr to (SimProcedure class name, kwargs_
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # Ld guesses the architecture, loads the binary, its dependencies and
        # performs relocations.
        ld = cle.Ld(filename, force_ida=force_ida, load_libs=load_libs)
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

        if use_sim_procedures == True:
            self.use_sim_procedures()

        self.mem = ld.memory
        self.vexer = VEXer(self.mem, self.arch, use_cache=self.arch.cache_irsb)

    def use_sim_procedures(self):
        """ Use simprocedures where we can """
        # Look for implemented libraries
        libs = self.__find_sim_libraries()
        for lib in libs:
            l.debug("[Simprocedures for external library: %s]" % lib)
            # Look for implemented functions
            fun = self.__find_sim_functions(lib)

            # Get the dictionary {function => symprocedure} for lib
            simfun = simuvex.procedures.SimProcedures[lib]

            # Replace the functions with simprocedures
            for f in fun:
                if not self.exclude_sim_procedure(f):
                    l.debug("@%s:" % f)
                    self.set_sim_procedure(self.main_binary, lib, f,
                                           simfun[f], None)
    def exclude_sim_procedure(self, f):
        return f in self.exclude_sim_procedures

    def __find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex"""
        simlibs = []

        libs = [os.path.basename(o.binary) for o in self.ld.shared_objects]
        for lib_name in libs:
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
        TODO: extend that to imports in shared libraries as well
        """
        simfunc = []

        functions = simuvex.procedures.SimProcedures[lib_name]
        imports = self.main_binary.imports

        for imp, addr in imports.iteritems():
            #l.debug("@%s:", imp)

            if imp in self.exclude_sim_procedures:
                l.debug("@%s:", imp)
                l.debug("\t -> excluded!")
                continue

            if imp in functions:
                #l.debug("\t -> found :)")
                simfunc.append(imp)
            else:
                l.debug("@%s:", imp)
                l.debug("\t -> not found :(. Setting ReturnUnconstrained instead")
                self.set_sim_procedure(self.main_binary, lib_name, imp,
                            simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                                                   None)

        return simfunc

    def binary_by_addr(self, addr):
        """ This method differs from Project_ida's one with same name"""
        return self.ld.addr_belongs_to_object(addr)

    def update_jmpslot_with_simprocedure(self, func_name, pseudo_addr, binary):
        """ Update a jump slot (GOT address referred to by a PLT slot) with the
        address of a simprocedure """
        self.ld.override_got_entry(func_name, pseudo_addr, binary)


from .errors import AngrMemoryError, AngrExitError
from .vexer import VEXer
from .cfg import CFG
