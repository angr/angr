import logging

import archinfo

from collections import defaultdict

from ...calling_conventions import SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion
from .atoms import GuardUse, Register, MemoryLocation, Tmp, Parameter
from .dataset import DataSet
from .definition import Definition
from .external_codeloc import ExternalCodeLocation
from .subject import SubjectType
from .undefined import undefined
from .uses import Uses


l = logging.getLogger(name=__name__)


class LiveDefinitions:

    __slots__ = ('arch', '_subject', '_track_tmps', 'analysis', 'register_definitions', 'stack_definitions',
                 'memory_definitions', 'tmp_definitions', 'register_uses', 'stack_uses', 'memory_uses',
                 'uses_by_codeloc', 'tmp_uses', 'all_definitions', )

    """
    Represents the internal state of the ReachingDefinitionsAnalysis.

    It contains definitions and uses for register, stack, memory, and temporary variables, uncovered during the analysis.

    :param angr.analyses.reaching_definitions.Subject: The subject being analysed.
    :param archinfo.Arch arch: The architecture targeted by the program.
    :param Boolean track_tmps: Only tells whether or not temporary variables should be taken into consideration when
                              representing the state of the analysis.
                              Should be set to true when the analysis has counted uses and definitions for temporary
                              variables, false otherwise.
    :param angr.analyses.analysis.Analysis analysis: The analysis that generated the state represented by this object.
    :param int rtoc_value: When the targeted architecture is ppc64, the initial function needs to know the `rtoc_value`.
    """
    def __init__(self, arch, subject, track_tmps=False, analysis=None, rtoc_value=None):

        # handy short-hands
        self.arch = arch
        self._subject = subject
        self._track_tmps = track_tmps
        self.analysis = analysis

        self.register_definitions = KeyedRegion()
        self.stack_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()
        self.tmp_definitions = {}
        self.all_definitions = set()

        self._set_initialization_values(subject, rtoc_value)

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.memory_uses = Uses()
        self.uses_by_codeloc = defaultdict(set)
        self.tmp_uses = defaultdict(set)

    def __repr__(self):
        ctnt = "LiveDefs, %d regdefs, %d stackdefs, %d memdefs" % (
                len(self.register_definitions),
                len(self.stack_definitions),
                len(self.memory_definitions),
                )
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    @property
    def dep_graph(self):
        return self.analysis.dep_graph

    def _set_initialization_values(self, subject, rtoc_value=None):
        if subject.type is SubjectType.Function:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError('The architecture being ppc64, the parameter `rtoc_value` should be provided.')

            self._initialize_function(
                subject.cc,
                subject.content.addr,
                rtoc_value,
            )
        elif subject.type is SubjectType.Block:
            pass

        return self

    def _initialize_function(self, cc, func_addr, rtoc_value=None):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp, ExternalCodeLocation(), DataSet(self.arch.initial_sp, self.arch.bits))
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)
        if self.arch.name.startswith('MIPS'):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9 = Register(self.arch.registers['t9'][0],self.arch.bytes)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet(func_addr,self.arch.bits))
            self.register_definitions.set_object(t9_def.offset,t9_def,t9_def.size)

        if cc is not None:
            for arg in cc.args:
                # initialize register parameters
                if type(arg) is SimRegArg:
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = Definition(reg, ExternalCodeLocation(), DataSet(Parameter(reg), self.arch.bits))
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif type(arg) is SimStackArg:
                    ml = MemoryLocation(self.arch.initial_sp + arg.stack_offset, self.arch.bytes)
                    sp_offset = SpOffset(arg.size * 8, arg.stack_offset)
                    ml_def = Definition(ml, ExternalCodeLocation(), DataSet(Parameter(sp_offset), self.arch.bits))
                    self.memory_definitions.set_object(ml.addr, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture dependent initialization
        if self.arch.name.lower().find('ppc64') > -1:
            offset, size = self.arch.registers['rtoc']
            rtoc = Register(offset, size)
            rtoc_def = Definition(rtoc, ExternalCodeLocation(), DataSet(rtoc_value, self.arch.bits))
            self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet(func_addr, self.arch.bits))
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self):
        rd = type(self)(
            self.arch,
            self._subject,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.stack_definitions = self.stack_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd.all_definitions = self.all_definitions.copy()

        return rd

    def get_sp(self):
        """
        Return the concrete value contained by the stack pointer.
        """
        sp_definitions = self.register_definitions.get_objects_by_offset(self.arch.sp_offset)

        assert len(sp_definitions) == 1
        [sp_definition] = sp_definitions

        # Assuming sp_definition has only one concrete value.
        return sp_definition.data.get_first_element()

    def merge(self, *others):

        state = self.copy()

        for other in others:  # type: LiveDefinitions
            state.register_definitions.merge(other.register_definitions)
            state.stack_definitions.merge(other.stack_definitions)
            state.memory_definitions.merge(other.memory_definitions)

            state.register_uses.merge(other.register_uses)
            state.stack_uses.merge(other.stack_uses)
            state.memory_uses.merge(other.memory_uses)

            state.all_definitions.update(other.all_definitions)

        return state

    def _cycle(self, code_loc):
        if code_loc != self.analysis.current_codeloc:
            self.analysis.current_codeloc = code_loc
            self.analysis.codeloc_uses = set()

    def kill_definitions(self, atom, code_loc, data=None, dummy=True):
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param Atom atom:
        :param CodeLocation code_loc:
        :param object data:
        :return: None
        """

        if data is None:
            data = DataSet(undefined, atom.size)

        self.kill_and_add_definition(atom, code_loc, data, dummy=dummy)

    def kill_and_add_definition(self, atom, code_loc, data, dummy=False):
        self._cycle(code_loc)

        if type(atom) is Register:
            definition = self._kill_and_add_register_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is SpOffset:
            definition = self._kill_and_add_stack_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is MemoryLocation:
            definition = self._kill_and_add_memory_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is Tmp:
            definition = self._add_tmp_definition(atom, code_loc, data)
        else:
            raise NotImplementedError()

        if definition is not None:
            self.all_definitions.add(definition)

            if self.dep_graph is not None:
                self.dep_graph.add_node(definition)
                for used in self.analysis.codeloc_uses:
                    # Moderately confusing misnomers. This is an edge from a def to a use, since the
                    # "uses" are actually the definitions that we're using and the "definition" is the
                    # new definition; i.e. The def that the old def is used to construct so this is
                    # really a graph where nodes are defs and edges are uses.
                    self.dep_graph.add_edge(used, definition)

        return definition

    def add_use(self, atom, code_loc):
        self._cycle(code_loc)
        self.analysis.codeloc_uses.update(self.get_definitions(atom))

        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is SpOffset:
            self._add_stack_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)
        elif type(atom) is Tmp:
            self._add_tmp_use(atom, code_loc)

    def add_use_by_def(self, def_, code_loc):
        if type(def_.atom) is Register:
            self._add_register_use_by_def(def_, code_loc)
        elif type(def_.atom) is SpOffset:
            self._add_stack_use_by_def(def_, code_loc)
        elif type(def_.atom) is MemoryLocation:
            self._add_memory_use_by_def(def_, code_loc)
        elif type(def_.atom) is Tmp:
            self._add_tmp_use_by_def(def_, code_loc)
        else:
            raise TypeError()

    def get_definitions(self, atom):
        if type(atom) is Register:
            return self.register_definitions.get_objects_by_offset(atom.reg_offset)
        elif type(atom) is SpOffset:
            return self.stack_definitions.get_objects_by_offset(atom.offset)
        elif type(atom) is MemoryLocation:
            return self.memory_definitions.get_objects_by_offset(atom.addr)
        elif type(atom) is Tmp:
            if self._track_tmps:
                return {self.tmp_definitions[atom.tmp_idx]}
            else:
                return self.tmp_definitions[atom.tmp_idx]
        else:
            raise TypeError()

    def mark_guard(self, code_loc, data, target):
        self._cycle(code_loc)
        atom = GuardUse(target)
        kinda_definition = Definition(atom, code_loc, data)

        if self.dep_graph is not None:
            self.dep_graph.add_node(kinda_definition)
            for used in self.analysis.codeloc_uses:
                self.dep_graph.add_edge(used, kinda_definition)

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom, code_loc, data, dummy=False):

        # FIXME: check correctness
        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)
        return definition

    def _kill_and_add_stack_definition(self, atom, code_loc, data, dummy=False):
        definition = Definition(atom, code_loc, data, dummy=dummy)
        self.stack_definitions.set_object(atom.offset, definition, data.bits // 8)
        return definition

    def _kill_and_add_memory_definition(self, atom, code_loc, data, dummy=False):
        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)
        return definition

    def _add_tmp_definition(self, atom, code_loc, data):

        if self._track_tmps:
            def_ = Definition(atom, code_loc, data)
            self.tmp_definitions[atom.tmp_idx] = def_
            return def_
        else:
            self.tmp_definitions[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
            return None

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)

        for current_def in current_defs:
            self._add_register_use_by_def(current_def, code_loc)

    def _add_register_use_by_def(self, def_, code_loc):
        self.register_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_stack_use(self, atom, code_loc):
        """

        :param SpOffset atom:
        :param code_loc:
        :return:
        """

        current_defs = self.stack_definitions.get_objects_by_offset(atom.offset)

        for current_def in current_defs:
            self._add_stack_use_by_def(current_def, code_loc)

    def _add_stack_use_by_def(self, def_, code_loc):
        self.stack_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

        if self.dep_graph is not None:
            self.dep_graph.add_edge(def_, code_loc)

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.memory_definitions.get_objects_by_offset(atom.addr)

        for current_def in current_defs:
            self._add_memory_use_by_def(current_def, code_loc)

    def _add_memory_use_by_def(self, def_, code_loc):
        self.memory_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_tmp_use(self, atom, code_loc):

        if self._track_tmps:
            def_ = self.tmp_definitions[atom.tmp_idx]
            self._add_tmp_use_by_def(def_, code_loc)
        else:
            defs = self.tmp_definitions[atom.tmp_idx]
            for d in defs:
                assert not type(d.atom) is Tmp
                self.add_use_by_def(d, code_loc)

    def _add_tmp_use_by_def(self, def_, code_loc):
        self.tmp_uses[def_.atom.tmp_idx].add(code_loc)
        self.uses_by_codeloc[code_loc].add(def_)
