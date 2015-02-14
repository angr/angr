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

    def __init__(self, state):
        '''
        Initializes the SimAction

        @param state: the state that's the SimAction is taking place in
        '''
        SimEvent.__init__(self, state, 'action')

    def __repr__(self):
        if self.sim_procedure is not None:
            location = "%s()" % self.sim_procedure
        else:
            location = "0x%x:%d" % (self.bbl_addr, self.stmt_idx)

        return "<%s %s %s>" % (self.__class__.__name__, location, self._desc())

    def _desc(self): #pylint:disable=no-self-use
        return "NO_DESCRIPTION"

    #def __getstate__(self):
    #   return { k: getattr(self, k) for k in sum([ c.__slots__ for c in self.__class__.mro() if hasattr(c, '__slots__')], []) } #pylint:disable=no-member
    #def __setstate__(self, s):
    #   for k,v in s.iteritems():
    #       setattr(self, k, v)

class SimActionData(SimAction):
    '''
    A Data action represents a read or a write from memory, registers, or a file.
    '''
    #__slots__ = [ 'objects' ]

    TMP = 'tmp'
    REG = 'reg'
    MEM = 'mem'

    READ = 'read'
    WRITE = 'write'

    def __init__(self, state, region_type, action, offset=None, tmp=None, addr=None, size=None, data=None, condition=None, fallback=None):
        super(SimActionData, self).__init__(state)
        self.type = region_type
        self.action = action

        self.offset = self._make_object(offset)
        self.addr = self._make_object(addr)
        self.tmp = self._make_object(tmp)
        self.size = self._make_object(size)
        self.data = self._make_object(data)
        self.condition = self._make_object(condition)
        self.fallback = self._make_object(fallback)

        if self.offset is not None: self.objects['offset'] = self.offset
        if self.addr is not None: self.objects['addr'] = self.addr
        if self.tmp is not None: self.objects['tmp'] = self.tmp
        if self.size is not None: self.objects['size'] = self.size
        if self.data is not None: self.objects['data'] = self.data
        if self.condition is not None: self.objects['condition'] = self.condition
        if self.fallback is not None: self.objects['fallback'] = self.fallback

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
        return [ a for a in [ self.addr, self.size, self.data, self.condition, self.fallback ] if a is not None ]

    def is_symbolic(self):
        for k in self.symbolic_keys:
            v = self.objects[k]
            if type(v) not in (int, long, float, str, bool, unicode) and v.symbolic:
                return True
        return False

    @property
    def tmp_deps(self):
        return frozenset.union(*[v.tmp_deps for v in self.all_objects])

    @property
    def reg_deps(self):
        return frozenset.union(*[v.reg_deps for v in self.all_objects])

    def _desc(self):
        return "%s/%s" % (self.type, self.action)

from .s_ast import SimAST
