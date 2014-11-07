# This module contains data structures for handling memory, code, and register references.

import logging
l = logging.getLogger('simuvex.s_action')

class SimActionObject(object):
    '''
    A SimActionObject tracks an AST and its dependencies.
    '''

    def __init__(self, ast, reg_deps=None, tmp_deps=None):
        self.ast = ast
        self.reg_deps = set() if reg_deps is None else reg_deps
        self.tmp_deps = set() if tmp_deps is None else tmp_deps

class SimAction(object):
    '''
    A SimAction represents a semantic action that an analyzed program performs.
    '''
    #__slots__ = [ 'bbl_addr', 'inst_addr', 'stmt_idx' ]

    def __init__(self, state):
        '''
        Initializes the SimAction

        @param bbl_addr: the (int) address of the instruction where the reference occurred
        @param inst_addr: the (int) address of the instruction where the reference occurred
        @param stmt_idx: the (int) statement index
        '''

        self.bbl_addr = state.bbl_addr
        self.inst_addr = None #state.inst_addr
        self.stmt_idx = state.stmt_idx

    def __repr__(self):
        return "<%s 0x%x:%d %s>" % (self.__class__.__name__, self.inst_addr, self.stmt_idx, self._desc())

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

    def __init__(self, state, region_type, action, **kwargs):
        super(SimActionData, self).__init__(state)
        self.type = region_type
        self.action = action

        self.objects = { }
        for k,v in kwargs.iteritems():
            if isinstance(k, SimAST):
                reg_deps = k._info.get('reg_deps', None)
                tmp_deps = k._info.get('tmp_deps', None)
                self.objects[k] = SimActionObject(v._a, reg_deps=reg_deps, tmp_deps=tmp_deps)
            elif isinstance(k, SimActionObject):
                self.objects[k] = v
            else:
                self.objects[k] = SimActionObject(k, reg_deps=None, tmp_deps=None)

    def is_symbolic(self):
        for k in self.symbolic_keys:
            v = self.objects[k]
            if type(v) not in (int, long, float, str, bool, unicode) and v.symbolic:
                return True
        return False

    @property
    def tmp_deps(self):
        return set.union(*[v.tmp_deps for v in self.objects.values()])

    @property
    def reg_deps(self):
        return set.union(*[v.reg_deps for v in self.objects.values()])

from .s_ast import SimAST
