# This module contains data structures for handling memory, code, and register references.

import logging
l = logging.getLogger('simuvex.s_action')

_noneset = frozenset()

from .s_event import SimEvent


class SimAction(SimEvent):
    """
    A SimAction represents a semantic action that an analyzed program performs.
    """
    #__slots__ = [ 'bbl_addr', 'inst_addr', 'stmt_idx' ]

    TMP = 'tmp'
    REG = 'reg'
    MEM = 'mem'

    def __init__(self, state, region_type):
        """
        Initializes the SimAction.

        :param state: the state that's the SimAction is taking place in.
        """
        SimEvent.__init__(self, state, 'action')
        self.type = region_type

    def __repr__(self):
        if self.sim_procedure is not None:
            location = "%s()" % self.sim_procedure
        else:
            if self.stmt_idx is not None:
                location = "0x%x:%d" % (self.bbl_addr, self.stmt_idx)
            else:
                location = "0x%x" % self.bbl_addr
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
        elif isinstance(v, SimActionObject):
            return v
        else:
            return SimActionObject(v, reg_deps=None, tmp_deps=None)

    @staticmethod
    def _copy_object(v):
        if isinstance(v, SimActionObject):
            return v.copy()
        else:
            return None

    @property
    def all_objects(self):
        raise NotImplementedError()

    @property
    def tmp_deps(self):
        return frozenset.union(*[v.tmp_deps for v in self.all_objects])

    @property
    def reg_deps(self):
        return frozenset.union(*[v.reg_deps for v in self.all_objects])

    def _copy_objects(self, c):
        raise NotImplementedError()

    def copy(self):
        c = self._copy_event()
        self._copy_objects(c)

        return c

    def downsize(self):
        """
        Clears some low-level details (that take up memory) out of the SimAction.
        """
        pass


class SimActionExit(SimAction):
    """
    An Exit action represents a (possibly conditional) jump.
    """

    CONDITIONAL = 'conditional'
    DEFAULT = 'default'

    def __init__(self, state, target, condition=None, exit_type=None):
        super(SimActionExit, self).__init__(state, "exit")
        if exit_type is not None:
            self.exit_type = exit_type
        elif condition is None:
            self.exit_type = SimActionExit.CONDITIONAL
        else:
            self.exit_type = SimActionExit.DEFAULT

        self.target = self._make_object(target)
        self.condition = self._make_object(condition)

    def _desc(self):
        return self.exit_type

    @property
    def all_objects(self):
        return [ a for a in ( self.target, self.condition ) if a is not None ]

    def _copy_objects(self, c):
        c.exit_type = self.exit_type
        c.target = self._copy_object(self.target)
        c.condition = self._copy_object(self.condition)


class SimActionConstraint(SimAction):
    """
    A constraint action represents an extra constraint added during execution of a path.
    """

    def __init__(self, state, constraint, condition=None):
        super(SimActionConstraint, self).__init__(state, "constraint")

        self.constraint = self._make_object(constraint)
        self.condition = self._make_object(condition)

    @property
    def all_objects(self):
        return [ a for a in ( self.constraint, self.condition ) if a is not None ]

    def _copy_objects(self, c):
        c.constraint = self._copy_object(self.constraint)
        c.condition = self._copy_object(self.condition)

    def _desc(self):
        s = '%s' % str(self.constraint)
        if self.condition is not None:
            s += ' (cond)'
        return s


class SimActionOperation(SimAction):
    """
    An action representing an operation between variables and/or constants.
    """

    def __init__(self, state, op, exprs):
        super(SimActionOperation, self).__init__(state, 'operation')

        self.op = op
        self.exprs = exprs

    @property
    def all_objects(self):
        return [ ex for ex in self.exprs if isinstance(ex, SimActionObject) ]

    def _copy_objects(self, c):
        c.op = self.op
        c.exprs = self.exprs[::]

    def _desc(self):
        return "operation/%s" % (self.op)


class SimActionData(SimAction):
    """
    A Data action represents a read or a write from memory, registers or a file.
    """
    #__slots__ = [ 'objects' ]

    READ = 'read'
    WRITE = 'write'
    OPERATE = 'operate'

    def __init__(self, state, region_type, action, tmp=None, addr=None, size=None, data=None, condition=None,
                 fallback=None, fd=None):
        super(SimActionData, self).__init__(state, region_type)
        self.action = action

        self._reg_dep = _noneset if addr is None or action != SimActionData.READ or not isinstance(addr, (int, long)) else frozenset((addr,))
        self._tmp_dep = _noneset if tmp is None or action != SimActionData.READ else frozenset((tmp,))

        self.tmp = tmp
        self.offset = None
        if region_type == 'reg':
            if isinstance(addr, (int, long)):
                self.offset = addr
            else:
                if addr.symbolic:
                    # FIXME: we should fix it by allowing .offset taking ASTs instead of concretizing it right away
                    l.warning('Concretizing a symbolic register offset in SimActionData.')
                    self.offset = state.se.any_int(addr)
                else:
                    # it's not symbolic
                    self.offset = state.se.exactly_int(addr)
        self.addr = self._make_object(addr)
        self.size = self._make_object(size)
        self.data = self._make_object(data)
        self.condition = self._make_object(condition)
        self.fallback = self._make_object(fallback)
        self.fd = self._make_object(fd)

        # these are extra attributes that expose low-level effects, such as the *actual*
        # written value
        self.actual_addrs = None
        # `actual_value` always stores whatever the data looks like in memory from left to right, therefore it's always
        # big-endian (if endianness matters)
        self.actual_value = None
        self.added_constraints = None

    def downsize(self):
        self.actual_addrs = None
        self.actual_value = None
        self.added_constraints = None

    @property
    def all_objects(self):
        return [ a for a in [ self.addr, self.size, self.data, self.condition, self.fallback, self.fd ] if a is not None ]

    @property
    def tmp_deps(self):
        return super(SimActionData, self).tmp_deps | self._tmp_dep

    @property
    def reg_deps(self):
        return super(SimActionData, self).reg_deps | self._reg_dep

    def _desc(self):
        return "%s/%s" % (self.type, self.action)

    def _copy_objects(self, c):
        c.action = self.action
        c.tmp = self.tmp
        c.addr = self._copy_object(self.addr)
        c.size = self._copy_object(self.size)
        c.data = self._copy_object(self.data)
        c.condition = self._copy_object(self.condition)
        c.fallback = self._copy_object(self.fallback)
        c.fd = self._copy_object(self.fd)

from .s_action_object import SimActionObject
