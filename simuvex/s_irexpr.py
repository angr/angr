#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import s_irop
import s_ccall
import s_value
import s_helpers
import s_options as o
import itertools
from .s_ref import SimTmpRead, SimRegRead, SimMemRead, SimMemRef

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
	pass

sym_counter = itertools.count()

class SimIRExpr:
	def __init__(self, expr, imark, stmt_idx, state, options, other_constraints = None):
		self.options = options
		self.state = state
		self.other_constraints = other_constraints if other_constraints else [ ]
		self.constraints = [ ]
		self.imark = imark
		self.stmt_idx = stmt_idx

		# effects tracking
		self.refs = [ ]
		self.post_processed = False

		self.sim_value = None
		self.expr = None
		self.type = None

		func_name = "handle_" + type(expr).__name__
		l.debug("Looking for handler for IRExpr %s" % (type(expr)))
		if hasattr(self, func_name):
			getattr(self, func_name)(expr)
		else:
			raise UnsupportedIRExprType("Unsupported expression type %s" % (type(expr)))

		self.post_process()

	# A post-processing step for the helpers. Simplifies constants, checks for memory references, etc.
	def post_process(self):
		if self.post_processed: return
		self.post_processed = True

		if o.SIMPLIFY_CONSTANTS in self.options:
			self.expr = symexec.simplify_expression(self.expr)

			# if the value is constant, replace it with a simple bitvecval
			simplifying_value = self.make_sim_value()
			if not simplifying_value.is_symbolic():
				self.expr = symexec.BitVecVal(simplifying_value.any(), simplifying_value.size())
				#print "NEW EXPR:", self.expr

		self.sim_value = self.make_sim_value()

		if self.sim_value.is_symbolic() and o.CONCRETIZE in self.options:
			self.concretize()

		if (
			o.MEMORY_MAPPED_REFS in self.options and
       			(o.SYMBOLIC in self.options or not self.sim_value.is_symbolic()) and
       			self.sim_value in self.state.memory and
       			self.sim_value.any() != self.imark.addr + self.imark.len
       		):
			self.refs.append(SimMemRef(self.imark.addr, self.stmt_idx, self.sim_value, self.reg_deps(), self.tmp_deps()))


	def size(self):
		if self.type is not None:
			return s_helpers.get_size(self.type)

		l.info("Calling out to sim_value.size(). MIGHT BE SLOW")
		return self.make_sim_value().size()/8

	def make_sim_value(self):
		return self.state.expr_value(self.expr, self.constraints + self.other_constraints)

	# Returns a set of registers that this IRExpr depends on.
	def reg_deps(self):
		return set([r.offset for r in self.refs if type(r) == SimRegRead])

	# Returns a set of tmps that this IRExpr depends on
	def tmp_deps(self):
		return set([r.tmp for r in self.refs if type(r) == SimTmpRead])

	def expr_and_constraints(self):
		return self.expr, self.constraints

	# translates several IRExprs, honoring mode and options and taking into account generated constraints along the way
	def translate_exprs(self, exprs):
		constraints = [ ]
		s_exprs = [ ]
	
		for a in exprs:
			e = self.translate_expr(a, constraints)
			s_exprs.append(e)
			constraints += e.constraints
	
		return s_exprs, constraints

	# translate a single IRExpr, honoring mode and options and so forth
	def translate_expr(self, expr, extra_constraints = None):
		if extra_constraints is None: extra_constraints = [ ]
		return SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.options, other_constraints = (self.other_constraints + extra_constraints))

	# track references in other expressions
	def track_expr_refs(self, *others):
		for e in others:
			self.refs.extend([ r for r in e.refs if o.SYMBOLIC in self.options or not r.is_symbolic() ])

	# Concretize this expression
	def concretize(self):
		size = self.size()
		concrete_value = self.sim_value.any()
		self.constraints.append(self.expr == concrete_value)
		self.expr = symexec.BitVecVal(concrete_value, size*8)

	###########################
	### expression handlers ###
	###########################

	def handle_Get(self, expr):
		size = s_helpers.get_size(expr.type)
		self.type = expr.type

		# get it!
		self.expr = self.state.reg_expr(expr.offset, size)

		# finish it and save the register references
		self.post_process()
		if expr.offset not in (self.state.arch.ip_offset,):
			simval = self.make_sim_value()
			self.refs.append(SimRegRead(self.imark.addr, self.stmt_idx, expr.offset, simval, size))
	
	def handle_op(self, expr):
		exprs, constraints = self.translate_exprs(expr.args())
		self.constraints.extend(constraints)

		# track memory access
		self.track_expr_refs(*exprs)
		self.expr = s_irop.translate(expr.op, [ e.expr for e in exprs ])

	handle_Unop = handle_op
	handle_Binop = handle_op
	handle_Triop = handle_op
	handle_Qop = handle_op

	def handle_RdTmp(self, expr):
		self.expr = self.state.tmp_expr(expr.tmp)
		size = self.size()/8 #TODO: improve speed

		# finish it and save the tmp reference
		self.post_process()
		if o.TMP_REFS in self.options:
			self.refs.append(SimTmpRead(self.imark.addr, self.stmt_idx, expr.tmp, s_value.SimValue(self.expr), size))

	def handle_Const(self, expr):
		self.expr = s_helpers.translate_irconst(expr.con)
	
	def handle_Load(self, expr):
		# size of the load
		size = s_helpers.get_size(expr.type)
		self.type = expr.type

		# get the address expression and track stuff
		addr = self.translate_expr(expr.addr)
		self.track_expr_refs(addr)
		self.constraints.extend(addr.constraints)

		# if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
		if o.DO_LOADS not in self.options or o.SYMBOLIC not in self.options and addr.sim_value.is_symbolic():
			self.expr = symexec.BitVec("sym_expr_0x%x_%d_%d" % (self.imark.addr, self.stmt_idx, sym_counter.next()), size*8)
		else:
			# load from memory and fix endianness
			self.expr = s_helpers.fix_endian(expr.endness, self.state.mem_expr(addr.sim_value, size, fix_endness=False))

		# finish it and save the mem read
		self.post_process()
		self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr.sim_value, self.make_sim_value(), size, addr.reg_deps(), addr.tmp_deps()))

	def handle_CCall(self, expr):
		exprs, constraints = self.translate_exprs(expr.args())
		self.constraints.extend(constraints)
		self.track_expr_refs(*exprs)

		if hasattr(s_ccall, expr.callee.name):
			s_args = [ e.expr for e in exprs ]
			func = getattr(s_ccall, expr.callee.name)
			retval, retval_constraints = func(self.state, *s_args)

			self.expr = retval
			self.constraints.extend(retval_constraints)
		else:
			raise Exception("Unsupported callee %s" % expr.callee.name)

	def handle_Mux0X(self, expr):
		cond = self.translate_expr(expr.cond)
		expr0 = self.translate_expr(expr.expr0, cond.constraints)
		exprX = self.translate_expr(expr.exprX, cond.constraints)

		# track references
		# NOTE: this is an over-approximation of the references in concrete mode
		self.track_expr_refs(cond)
		self.track_expr_refs(expr0)
		self.track_expr_refs(exprX)

		cond0_constraints = symexec.And(*([ cond.expr == 0 ] + expr0.constraints + cond.constraints ))
		condX_constraints = symexec.And(*([ cond.expr != 0 ] + exprX.constraints + cond.constraints ))

		self.expr = symexec.If(cond.expr == 0, expr0.expr, exprX.expr)
		self.constraints.append(symexec.Or(cond0_constraints, condX_constraints))
