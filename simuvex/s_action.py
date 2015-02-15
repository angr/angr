# This module contains data structures for handling memory, code, and register references.

import logging
l = logging.getLogger('simuvex.s_action')

_noneset = frozenset()

class SimActionObject(object):
    '''
    A SimActionObject tracks an AST and its dependencies.
    '''

    def __init__(self, ast, reg_deps=None, tmp_deps=None):
        self.ast = ast
        self.reg_deps = _noneset if reg_deps is None else reg_deps
        self.tmp_deps = _noneset if tmp_deps is None else tmp_deps

from .s_event import SimEvent
class SimAction(SimEvent):
    '''
    A SimAction represents a semantic action that an analyzed program performs.
    '''
    #__slots__ = [ 'bbl_addr', 'inst_addr', 'stmt_idx' ]

    TMP = 'tmp'
    REG = 'reg'
    MEM = 'mem'

    def __init__(self, state, region_type):
        '''
        Initializes the SimAction

        @param state: the state that's the SimAction is taking place in
        '''
        SimEvent.__init__(self, state, 'action')
        self.type = region_type

    def __repr__(self):
        if self.sim_procedure is not None:
            location = "%s()" % self.sim_procedure
        else:
            location = "0x%x:%d" % (self.bbl_addr, self.stmt_idx)

        return "<%s %s %s>" % (self.__class__.__name__, location, self._desc())

    def _desc(self):
        raise NotImplementedError()

    #def __getstate__(self):
    #   return { k: getattr(self, k) for k in sum([ c.__slots__ for c in self.__class__.mro() if hasattr(c, '__slots__')], []) } #pylint:disable=no-member
    #def __setstate__(self, s):
    #   for k,v in s.iteritems():
    #       setattr(self, k, v)

    @staticmethod
    def _make_object(v):
        if v is None:
            return None
        elif isinstance(v, SimAST):
            reg_deps = v._info.get('reg_deps', None)
            tmp_deps = v._info.get('tmp_deps', None)
            return SimActionObject(v._a, reg_deps=reg_deps, tmp_deps=tmp_deps)
        elif isinstance(v, SimActionObject):
            return v
        else:
            return SimActionObject(v, reg_deps=None, tmp_deps=None)

    @property
    def all_objects(self):
        raise NotImplementedError()

    @property
    def tmp_deps(self):
        raise NotImplementedError()

    @property
    def reg_deps(self):
        raise NotImplementedError()

class SimActionExit(SimAction):
    '''
    An Exit action represents a (possibly conditional) jump.
    '''

    CONDITIONAL = 'conditional'
    DEFAULT = 'default'

    def __init__(self, state, exit_type, target, condition=None):
        super(SimActionExit, self).__init__(state, "exit")
        self.exit_type = exit_type

        self.target = self._make_object(target)
        self.condition = self._make_object(condition)

    def _desc(self):
        return self.exit_type

    @property
    def all_objects(self):
        return [ a for a in ( self.target, self.condition ) if a is not None ]

    @property
    def tmp_deps(self):
        return frozenset.union(*[v.tmp_deps for v in self.all_objects])

    @property
    def reg_deps(self):
        return frozenset.union(*[v.reg_deps for v in self.all_objects])

class SimActionData(SimAction):
    '''
    A Data action represents a read or a write from memory, registers, or a file.
    '''
    #__slots__ = [ 'objects' ]

    READ = 'read'
    WRITE = 'write'

    def __init__(self, state, region_type, action, offset=None, tmp=None, addr=None, size=None, data=None, condition=None, fallback=None):
        super(SimActionData, self).__init__(state, region_type)
        self.action = action

        self._reg_dep = _noneset if offset is None else frozenset((offset,))
        self._tmp_dep = _noneset if tmp is None else frozenset((tmp,))

        self.offset = self._make_object(offset)
        self.addr = self._make_object(addr)
        self.tmp = self._make_object(tmp)
        self.size = self._make_object(size)
        self.data = self._make_object(data)
        self.condition = self._make_object(condition)
        self.fallback = self._make_object(fallback)

    @property
    def all_objects(self):
        return [ a for a in [ self.addr, self.size, self.data, self.condition, self.fallback ] if a is not None ]

    @property
    def tmp_deps(self):
        return frozenset.union(self._tmp_dep, *[v.tmp_deps for v in self.all_objects])

    @property
    def reg_deps(self):
        return frozenset.union(self._reg_dep, *[v.reg_deps for v in self.all_objects])

    def _desc(self):
        return "%s/%s" % (self.type, self.action)

from .s_ast import SimAST
