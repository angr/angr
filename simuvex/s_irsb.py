#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

# because pylint can't load pyvex
# pylint: disable=F0401

import itertools
import json
import types

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

from .s_run import SimRun
#import vexecutor

sirsb_count = itertools.count()

# The initialization magic we play in SimRun requires us to disable these warnings, unfortunately
## pylint: disable=W0231

class SimIRSB(SimRun):
    '''Simbolically parses a basic block.

          irsb - the pyvex IRSB to parse
          provided_state - the symbolic state at the beginning of the block
          id - the ID of the basic block
          whitelist - a whitelist of the statements to execute (default: all)
          last_stmt - the statement to stop execution at
    '''

    # The attribute "index" is used by angr.cdg
    #__slots__ = [ 'irsb', 'first_imark', 'last_imark', 'addr', 'id', 'whitelist', 'last_stmt', 'has_default_exit', 'num_stmts', 'next_expr', 'statements', 'conditional_exits', 'default_exit', 'postcall_exit', 'index', 'default_exit_guard' ]

    def __init__(self, irsb, irsb_id=None, whitelist=None, last_stmt=None):
        if irsb.size() == 0:
            raise SimIRSBError("Empty IRSB passed to SimIRSB.")

        self.irsb = irsb
        self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
        self.last_imark = self.first_imark
        self.addr = self.first_imark.addr
        self.id = "%x" % self.first_imark.addr if irsb_id is None else irsb_id
        self.whitelist = whitelist
        self.last_stmt = last_stmt
        self.default_exit_guard = self.state.se.BoolVal(last_stmt is None)

        self.state._inspect('irsb', BP_BEFORE, address=self.addr)

        # this stuff will be filled out during the analysis
        self.num_stmts = 0
        self.next_expr = None
        self.statements = [ ]
        self.conditional_exits = [ ]
        self.default_exit = None
        self.postcall_exit = None
        self.has_default_exit = False

        if o.BLOCK_SCOPE_CONSTRAINTS in self.state.options and 'solver_engine' in self.state.plugins:
            self.state.release_plugin('solver_engine')

        #if self.state.is_native():
        #    try:
        #        self.state.native_env.vexecute(self.irsb)
        #    except (vexecutor.MemoryBoundsError, vexecutor.MemoryValidityError):
        #        l.debug("Vexecutor raised an exception at statement %d", self.state.native_env.statement_index)
        #        self.whitelist = set(range(self.state.native_env.statement_index, len(self.irsb.statements())))
        #        self._handle_irsb()
        #else:
        if o.SIMIRSB_FASTPATH not in self.state.options:
            self._handle_irsb()
        else:
            self._handle_irsb_fastpath()

        if o.DOWNSIZE_Z3 in self.state.options:
            self.initial_state.downsize()

        # It's for debugging
        # irsb.pp()
        # if whitelist != None:
        #    print "======== whitelisted statements ========"
        #    pos = 0
        #    for s in self.statements:
        #        print "%d: " % whitelist[pos],
        #        s.stmt.pp()
        #        print ""
        #        pos += 1
        #    print "======== end ========"

        self.state._inspect('irsb', BP_AFTER)

    def __repr__(self):
        return "<SimIRSB %s>" % self.id_str

    def _fastpath_irexpr(self, expr, temps, regs):
        if type(expr) == pyvex.IRExpr.Const:
            return translate_irconst(self.state, expr.con)
        elif type(expr) == pyvex.IRExpr.RdTmp:
            return temps[expr.tmp]
        elif type(expr) == pyvex.IRExpr.Get and expr.offset in regs:
            return regs[expr.offset]
        else:
            return None

    def _handle_irsb_fastpath(self):
        temps = { }
        regs = { }
        guard = self.state.se.true

        for stmt in self.irsb.statements():
            if type(stmt) == pyvex.IRStmt.IMark:
                self.last_imark = stmt
            elif type(stmt) == pyvex.IRStmt.Exit:
                l.debug("%s adding conditional exit", self)
                e = SimExit(expr=self.state.BVV(stmt.offsIP, self.state.arch.bits), guard=guard, state=self.state, source=self.state.BVV(self.last_imark.addr, self.state.arch.bits), jumpkind=self.irsb.jumpkind, simplify=False)
                self.conditional_exits.append(e)
                self.add_exits(e)
            elif type(stmt) == pyvex.IRStmt.WrTmp:
                temps[stmt.tmp] = self._fastpath_irexpr(stmt.data, temps, regs)
            elif type(stmt) == pyvex.IRStmt.Put:
                regs[stmt.offset] = self._fastpath_irexpr(stmt.data, temps, regs)
            else:
                continue

        next_expr = self._fastpath_irexpr(self.irsb.next, temps, regs)
        if next_expr is not None:
            self.has_default_exit = True
            self.default_exit = SimExit(expr=next_expr, guard=guard, state=self.state, jumpkind=self.irsb.jumpkind, simplify=False, source=self.state.BVV(self.last_imark.addr, self.state.arch.bits))
            self.add_exits(self.default_exit)

    def _handle_irsb(self):
        if o.BREAK_SIRSB_START in self.state.options:
            import ipdb
            ipdb.set_trace()

        # finish the initial setup
        self._prepare_temps(self.state)

        # handle the statements
        try:
            self._handle_statements()
        except SimError:
            l.warning("%s hit a SimError when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", self, exc_info=True)

        # FUck. ARM
        self.postcall_exit = None
        for e in self.conditional_exits:
            if o.DO_RET_EMULATION in e.state.options and e.jumpkind == "Ijk_Call":
                l.debug("%s adding postcall exit.", self)
                self.postcall_exit = SimExit(sirsb_postcall = self, state=e.state, simple_postcall = (o.SYMBOLIC not in self.state.options))

        # some finalization
        self.num_stmts = len(self.irsb.statements())

        # If there was an error, and not all the statements were processed,
        # then this block does not have a default exit. This can happen if
        # the block has an unavoidable "conditional" exit or if there's a legitimate
        # error in the simulation
        self.default_exit = None
        if self.has_default_exit:
            self.next_expr = SimIRExpr(self.irsb.next, self.last_imark, self.num_stmts, self.state, self.irsb.tyenv)

            self.add_refs(*self.next_expr.refs)

            # TODO: in static mode, we probably only want to count one
            #    code ref even when multiple exits are going to the same
            #    place.
            self.add_refs(SimCodeRef(self.last_imark.addr, self.num_stmts, self.next_expr.expr, self.next_expr.reg_deps(), self.next_expr.tmp_deps()))

            # the default exit
            if self.irsb.jumpkind == "Ijk_Call" and o.CALLLESS in self.state.options:
                l.debug("GOIN' CALLLESS!")
                ret = simuvex.SimProcedures['stubs']['ReturnUnconstrained'](self.state, addr=self.addr, stmt_from=len(self.statements), inline=True)
                self.copy_refs(ret)
                self.copy_exits(ret)
            else:
                self.default_exit = SimExit(sirsb_exit = self, default_exit=True)
                l.debug("%s adding default exit.", self)
                self.add_exits(self.default_exit)

            # ret emulation
            if o.DO_RET_EMULATION in self.state.options and self.irsb.jumpkind == "Ijk_Call":
                l.debug("%s adding postcall exit.", self)
                self.postcall_exit = SimExit(sirsb_postcall = self, simple_postcall = (o.SYMBOLIC not in self.state.options))
        else:
            l.debug("%s has no default exit", self)

        # this goes last, for Fish's stuff
        if self.postcall_exit is not None:
            l.debug("%s actually adding postcall!", self)
            self.add_exits(self.postcall_exit)

        if o.BREAK_SIRSB_END in self.state.options:
            import ipdb
            ipdb.set_trace()


    # This function receives an initial state and imark and processes a list of pyvex.IRStmts
    # It returns a final state, last imark, and a list of SimIRStmts
    def _handle_statements(self):
        # Translate all statements until something errors out
        for stmt_idx, stmt in enumerate(self.irsb.statements()):
            if self.last_stmt is not None and stmt_idx > self.last_stmt:
                l.debug("%s stopping analysis at statment %d.", self, self.last_stmt)
                break

            #l.debug("%s processing statement %s of max %s", self, stmt_idx, self.last_stmt)

            # we'll pass in the imark to the statements
            if type(stmt) == pyvex.IRStmt.IMark:
                self.state._inspect('instruction', BP_AFTER)

                l.debug("IMark: 0x%x", stmt.addr)
                self.last_imark = stmt
                if o.INSTRUCTION_SCOPE_CONSTRAINTS in self.state.options:
                    if 'solver_engine' in self.state.plugins:
                        self.state.release_plugin('solver_engine')

                self.state._inspect('instruction', BP_BEFORE, instruction=self.last_imark.addr)

            if self.whitelist is not None and stmt_idx not in self.whitelist:
                l.debug("... whitelist says skip it!")
                continue
            elif self.whitelist is not None:
                l.debug("... whitelist says analyze it!")

            # process it!
            self.state._inspect('statement', BP_BEFORE, statement=stmt_idx)
            s_stmt = SimIRStmt(stmt, self.last_imark, self.addr, stmt_idx, self.state, self.irsb.tyenv)
            self.add_refs(*s_stmt.refs)
            self.statements.append(s_stmt)
            self.state._inspect('statement', BP_AFTER)

            # for the exits, put *not* taking the exit on the list of constraints so
            # that we can continue on. Otherwise, add the constraints
            if type(stmt) == pyvex.IRStmt.Exit:
                e = SimExit(sexit = s_stmt)
                self.default_exit_guard = self.state.se.And(self.default_exit_guard, self.state.se.Not(e.guard))

                l.debug("%s adding conditional exit", self)
                self.conditional_exits.append(e)
                self.add_exits(e)

                if o.SINGLE_EXIT in self.state.options and not self.state.se.symbolic(e.guard) and e.reachable() != 0:
                    l.debug("%s returning after taken exit due to SINGLE_EXIT option.", self)
                    return

        if self.last_stmt is None:
            self.has_default_exit = True

    def _prepare_temps(self, state):
        state.temps = { }

        # prepare symbolic variables for the statements if we're using SYMBOLIC_TEMPS
        if o.SYMBOLIC_TEMPS in self.state.options:
            sirsb_num = sirsb_count.next()
            for n, t in enumerate(self.irsb.tyenv.types()):
                state.temps[n] = self.state.BV('temp_%s_%d_t%d' % (self.id, sirsb_num, n), size_bits(t))
            l.debug("%s prepared %d symbolic temps.", len(state.temps), self)

    # Returns a list of instructions that are part of this block.
    def imark_addrs(self):
        return [ i.addr for i in self.irsb.statements() if type(i) == pyvex.IRStmt.IMark ]

    def reanalyze(self, mode=None, new_state=None, irsb_id=None, whitelist=None):
        new_state = self.initial_state.copy() if new_state is None else new_state

        if mode is not None:
            new_state.mode = mode
            new_state.options = set(o.default_options[mode])

        irsb_id = self.id if irsb_id is None else irsb_id
        whitelist = self.whitelist if whitelist is None else whitelist
        return SimIRSB(new_state, self.irsb, irsb_id=irsb_id, whitelist=whitelist) #pylint:disable=E1124

    def _crawl_vex(self, p):
        attr_blacklist = {'wrapped'}
        l.debug("got type %s", p.__class__)

        if type(p) in (int, str, float, long, bool):
            return p

        if type(p) in (list, tuple):
            return [ self._crawl_vex(e) for e in p ]
        if type(p) is (dict):
            return { k:self._crawl_vex(p[k]) for k in p }

        attr_keys = set()
        for k in dir(p):
            if k in attr_blacklist:
                continue

            if k.startswith('_'):
                continue

            if type(getattr(p, k)) in (types.BuiltinFunctionType, types.BuiltinMethodType, types.FunctionType, types.ClassType, type):
                continue

            attr_keys.add(k)

        vdict = { }
        for k in attr_keys:
            l.debug("crawling %s!", k)
            vdict[k] = self._crawl_vex(getattr(p, k))

        if type(p) is pyvex.IRSB:
            vdict['statements'] = self._crawl_vex(p.statements())
            vdict['instructions'] = self._crawl_vex(p.instructions())
        elif type(p) is pyvex.IRTypeEnv:
            vdict['types'] = self._crawl_vex(p.types())

        return vdict

    def to_json(self):
        return json.dumps(self._crawl_vex(self.irsb))

import pyvex
from .s_irstmt import SimIRStmt
from .s_helpers import size_bits, translate_irconst
from .s_exit import SimExit
import simuvex.s_options as o
from .s_irexpr import SimIRExpr
from .s_ref import SimCodeRef
import simuvex
from .plugins.inspect import BP_AFTER, BP_BEFORE
from .s_errors import SimIRSBError, SimError
