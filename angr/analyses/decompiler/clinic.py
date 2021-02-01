from collections import defaultdict
import logging
from typing import Dict, List, Tuple, Set, Optional, Iterable, Union, Type, TYPE_CHECKING

import networkx

import ailment

from ...knowledge_base import KnowledgeBase
from ...codenode import BlockNode
from ...utils import timethis
from ...calling_conventions import SimRegArg, SimStackArg, SimFunctionArgument
from ...sim_type import SimTypeChar, SimTypeInt, SimTypeLongLong, SimTypeShort, SimTypeFunction, SimTypeBottom
from ...sim_variable import SimVariable, SimStackVariable, SimRegisterVariable
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...procedures.stubs.UnresolvableCallTarget import UnresolvableCallTarget
from ...procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from .. import Analysis, register_analysis
from ..cfg.cfg_base import CFGBase
from .ailgraph_walker import AILGraphWalker
from .ailblock_walker import AILBlockWalker
from .optimization_passes import get_default_optimization_passes, OptimizationPassStage

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from .peephole_optimizations import PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase


l = logging.getLogger(name=__name__)


class Clinic(Analysis):
    """
    A Clinic deals with AILments.
    """
    def __init__(self, func,
                 remove_dead_memdefs=True,
                 exception_edges=False,
                 sp_tracker_track_memory=True,
                 optimization_passes=None,
                 cfg=None,
                 peephole_optimizations: Optional[Iterable[Union[Type['PeepholeOptimizationStmtBase'],Type['PeepholeOptimizationExprBase']]]]=None,
                 ):
        if not func.normalized:
            raise ValueError("Decompilation must work on normalized function graphs.")

        self.function = func

        self.graph = None
        self.arg_list = None
        self.variable_kb = None

        self._func_graph: Optional[networkx.DiGraph] = None
        self._ail_manager = None
        self._blocks_by_addr_and_size = { }

        self._remove_dead_memdefs = remove_dead_memdefs
        self._exception_edges = exception_edges
        self._sp_tracker_track_memory = sp_tracker_track_memory
        self._cfg: Optional['CFGModel'] = cfg
        self.peephole_optimizations = peephole_optimizations

        # sanity checks
        if not self.kb.functions:
            l.warning('No function is available in kb.functions. It will lead to a suboptimal conversion result.')

        if optimization_passes is not None:
            self._optimization_passes = optimization_passes
        else:
            self._optimization_passes = get_default_optimization_passes(self.project.arch, self.project.simos.name)
            l.debug("Get %d optimization passes for the current binary.", len(self._optimization_passes))

        self._analyze()

    #
    # Public methods
    #

    def block(self, addr, size):
        """
        Get the converted block at the given specific address with the given size.

        :param int addr:
        :param int size:
        :return:
        """

        try:
            return self._blocks_by_addr_and_size[(addr, size)]
        except KeyError:
            return None

    def dbg_repr(self):
        """

        :return:
        """

        s = ""

        for block in sorted(self.graph.nodes(), key=lambda x: x.addr):
            s += str(block) + "\n\n"

        return s

    #
    # Private methods
    #

    def _analyze(self):

        # Set up the function graph according to configurations
        self._set_function_graph()

        # Remove alignment blocks
        self._remove_alignment_blocks()

        # if the graph is empty, don't continue
        if not self._func_graph:
            return

        # Make sure calling conventions of all functions have been recovered
        self._recover_calling_conventions()

        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        # Track stack pointers
        spt = self._track_stack_pointers()

        # Convert VEX blocks to AIL blocks and then simplify them

        self._convert_all()

        ail_graph = self._make_ailgraph()

        # Fix "fake" indirect jumps and calls
        ail_graph = self._replace_single_target_indirect_transitions(ail_graph)

        # Make returns
        ail_graph = self._make_returns(ail_graph)

        # Simplify blocks
        ail_graph = self._simplify_blocks(ail_graph, stack_pointer_tracker=spt)

        # Run simplification passes
        ail_graph = self._run_simplification_passes(ail_graph,
                                                    stage=OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION)

        # Simplify the entire function for the first time
        self._simplify_function(ail_graph, unify_variables=False)

        # clear _blocks_by_addr_and_size so no one can use it again
        # TODO: Totally remove this dict
        self._blocks_by_addr_and_size = None

        # Make call-sites
        self._make_callsites(ail_graph, stack_pointer_tracker=spt)

        # Simplify the entire function for the second time
        self._simplify_function(ail_graph, unify_variables=True)

        # Make function arguments
        arg_list = self._make_argument_list()

        # Recover variables on AIL blocks
        variable_kb = self._recover_and_link_variables(ail_graph, arg_list)

        # Make function prototype
        self._make_function_prototype(arg_list, variable_kb)

        # Run simplification passes
        ail_graph = self._run_simplification_passes(ail_graph, stage=OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION)

        self.graph = ail_graph
        self.arg_list = arg_list
        self.variable_kb = variable_kb

    @timethis
    def _set_function_graph(self):
        self._func_graph = self.function.graph_ex(exception_edges=self._exception_edges)

    @timethis
    def _remove_alignment_blocks(self):
        """
        Alignment blocks are basic blocks that only consist of nops. They should not be included in the graph.
        """
        for node in list(self._func_graph.nodes()):
            if self._func_graph.in_degree(node) == 0 and \
                    CFGBase._is_noop_block(self.project.arch, self.project.factory.block(node.addr, node.size)):
                self._func_graph.remove_node(node)

    @timethis
    def _recover_calling_conventions(self):
        self.project.analyses.CompleteCallingConventions()

    @timethis
    def _track_stack_pointers(self):
        """
        For each instruction, track its stack pointer offset and stack base pointer offset.

        :return: None
        """

        regs = {self.project.arch.sp_offset}
        if hasattr(self.project.arch, 'bp_offset') and self.project.arch.bp_offset is not None:
            regs.add(self.project.arch.bp_offset)
        spt = self.project.analyses.StackPointerTracker(self.function, regs, track_memory=self._sp_tracker_track_memory)
        if spt.inconsistent_for(self.project.arch.sp_offset):
            l.warning("Inconsistency found during stack pointer tracking. Decompilation results might be incorrect.")
        return spt

    @timethis
    def _convert_all(self):
        """
        Convert all VEX blocks in the function graph to AIL blocks, and fill self._blocks.

        :return:    None
        """

        for block_node in self._func_graph.nodes():
            ail_block = self._convert(block_node)

            if type(ail_block) is ailment.Block:
                self._blocks_by_addr_and_size[(block_node.addr, block_node.size)] = ail_block

    def _convert(self, block_node):
        """
        Convert a VEX block to an AIL block.

        :param block_node:  A BlockNode instance.
        :return:            An converted AIL block.
        :rtype:             ailment.Block
        """

        if not type(block_node) is BlockNode:
            return block_node

        block = self.project.factory.block(block_node.addr, block_node.size)

        ail_block = ailment.IRSBConverter.convert(block.vex, self._ail_manager)
        return ail_block

    @timethis
    def _replace_single_target_indirect_transitions(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Remove single-target indirect jumps and calls and replace them with direct jumps or calls.
        """
        if self._cfg is None:
            return ail_graph

        for block in ail_graph.nodes():
            if not block.statements:
                continue
            last_stmt = block.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Call) and not isinstance(last_stmt.target, ailment.Expr.Const):
                # indirect call
                # consult CFG to see if this is a call with a single successor
                node = self._cfg.get_any_node(block.addr)
                if node is None:
                    continue
                successors = self._cfg.get_successors(node, excluding_fakeret=True, jumpkind='Ijk_Call')
                if len(successors) == 1 and \
                        not isinstance(self.project.hooked_by(successors[0].addr), UnresolvableCallTarget):
                    # found a single successor - replace the last statement
                    new_last_stmt = last_stmt.copy()
                    new_last_stmt.target = ailment.Expr.Const(None, None, successors[0].addr, last_stmt.target.bits)
                    block.statements[-1] = new_last_stmt

            elif isinstance(last_stmt, ailment.Stmt.Jump) and not isinstance(last_stmt.target, ailment.Expr.Const):
                # indirect jump
                # consult CFG to see if there is a jump with a single successor
                node = self._cfg.get_any_node(block.addr)
                if node is None:
                    continue
                successors = self._cfg.get_successors(node, excluding_fakeret=True, jumpkind='Ijk_Boring')
                if len(successors) == 1 and \
                        not isinstance(self.project.hooked_by(successors[0].addr), UnresolvableJumpTarget):
                    # found a single successor - replace the last statement
                    new_last_stmt = last_stmt.copy()
                    new_last_stmt.target = ailment.Expr.Const(None, None, successors[0].addr, last_stmt.target.bits)
                    block.statements[-1] = new_last_stmt

        return ail_graph

    @timethis
    def _make_ailgraph(self) -> networkx.DiGraph:
        graph = self._function_graph_to_ail_graph(self._func_graph)
        return graph

    @timethis
    def _simplify_blocks(self, ail_graph: networkx.DiGraph, stack_pointer_tracker=None):
        """
        Simplify all blocks in self._blocks.

        :param ail_graph:               The AIL function graph.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :return:                        None
        """

        blocks_by_addr_and_size = {}

        for ail_block in ail_graph.nodes():
            simplified = self._simplify_block(ail_block, stack_pointer_tracker=stack_pointer_tracker)
            key = ail_block.addr, ail_block.original_size
            blocks_by_addr_and_size[key] = simplified

        graph = self._function_graph_to_ail_graph(self._func_graph, blocks_by_addr_and_size=blocks_by_addr_and_size)
        return graph

    def _simplify_block(self, ail_block, stack_pointer_tracker=None):
        """
        Simplify a single AIL block.

        :param ailment.Block ail_block: The AIL block to simplify.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :return:                        A simplified AIL block.
        """

        simp = self.project.analyses.AILBlockSimplifier(
            ail_block,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_pointer_tracker=stack_pointer_tracker,
            peephole_optimizations=self.peephole_optimizations,
        )
        return simp.result_block

    @timethis
    def _simplify_function(self, ail_graph, unify_variables=False, max_iterations: int=4) -> None:
        """
        Simplify the entire function until it reaches a fixed point.
        """

        for _ in range(max_iterations):
            simplified = self._simplify_function_once(ail_graph, unify_variables=unify_variables)
            if not simplified:
                break

    @timethis
    def _simplify_function_once(self, ail_graph, unify_variables=False):
        """
        Simplify the entire function once.

        :return:    None
        """

        # Computing reaching definitions
        rd = self.project.analyses.ReachingDefinitions(subject=self.function, func_graph=ail_graph,
                                                       observe_callback=self._simplify_function_rd_observe_callback)

        simp = self.project.analyses.AILSimplifier(
            self.function,
            func_graph=ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            reaching_definitions=rd,
            unify_variables=unify_variables,
        )
        if not simp.simplified:
            return False

        def _handler(node):
            return simp.blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return True

    @timethis
    def _run_simplification_passes(self, ail_graph, stage:int=OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION):

        addr_and_idx_to_blocks: Dict[Tuple[int,Optional[int]],ailment.Block] = { }
        addr_to_blocks: Dict[int,Set[ailment.Block]] = defaultdict(set)

        # update blocks_map to allow node_addr to node lookup
        def _updatedict_handler(node):
            addr_and_idx_to_blocks[(node.addr, node.idx)] = node
            addr_to_blocks[node.addr].add(node)
        AILGraphWalker(ail_graph, _updatedict_handler).walk()

        # Run each pass
        for pass_ in self._optimization_passes:

            if pass_.STAGE != stage:
                continue

            analysis = getattr(self.project.analyses, pass_.__name__)

            a = analysis(self.function, blocks_by_addr=addr_to_blocks, blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                         graph=ail_graph)
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph

        return ail_graph

    @timethis
    def _make_argument_list(self) -> List[SimVariable]:
        if self.function.calling_convention is not None:
            args: List[SimFunctionArgument] = self.function.calling_convention.args
            arg_vars: List[SimVariable] = [ ]
            if args:
                for idx, arg in enumerate(args):
                    if isinstance(arg, SimRegArg):
                        argvar = SimRegisterVariable(
                            self.project.arch.registers[arg.reg_name][0],
                            arg.size,
                            ident="arg_%d" % idx,
                            name="a%d" % idx,
                            region=self.function.addr,
                        )
                    elif isinstance(arg, SimStackArg):
                        argvar = SimStackVariable(
                            arg.stack_offset,
                            arg.size,
                            base='bp',
                            ident="arg_%d" % idx,
                            name="a%d" % idx,
                            region=self.function.addr,
                        )
                    else:
                        raise TypeError("Unsupported function argument type %s." % type(arg))
                    arg_vars.append(argvar)
            return arg_vars
        return [ ]

    @timethis
    def _make_callsites(self, ail_graph, stack_pointer_tracker=None):
        """
        Simplify all function call statements.

        :return:    None
        """

        # Computing reaching definitions
        rd = self.project.analyses.ReachingDefinitions(subject=self.function, func_graph=ail_graph,
                                                       observe_callback=self._make_callsites_rd_observe_callback)

        def _handler(block):
            csm = self.project.analyses.AILCallSiteMaker(block, reaching_definitions=rd)
            if csm.result_block:
                ail_block = csm.result_block
                simp = self.project.analyses.AILBlockSimplifier(ail_block,
                                                                stack_pointer_tracker=stack_pointer_tracker,
                                                                peephole_optimizations=self.peephole_optimizations,
                                                                )
                return simp.result_block
            return None

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    @timethis
    def _make_returns(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Work on each return statement and fill in its return expressions.
        """

        if self.function.calling_convention is None:
            # unknown calling convention. cannot do much about return expressions.
            return ail_graph

        # Block walker

        def _handle_Return(stmt_idx: int, stmt: ailment.Stmt.Return, block: Optional[ailment.Block]):  # pylint:disable=unused-argument
            if block is not None \
                    and not stmt.ret_exprs \
                    and self.function.calling_convention.ret_val is not None:
                new_stmt = stmt.copy()
                ret_val = self.function.calling_convention.ret_val
                if isinstance(ret_val, SimRegArg):
                    reg = self.project.arch.registers[ret_val.reg_name]
                    new_stmt.ret_exprs.append(ailment.Expr.Register(None, None, reg[0],
                                                                    reg[1] * self.project.arch.byte_width))
                else:
                    l.warning("Unsupported type of return expression %s.",
                              type(self.function.calling_convention.ret_val))
                block.statements[stmt_idx] = new_stmt


        def _handler(block):
            walker = AILBlockWalker()
            # we don't need to handle any statement besides Returns
            walker.stmt_handlers.clear()
            walker.expr_handlers.clear()
            walker.stmt_handlers[ailment.Stmt.Return] = _handle_Return
            walker.walk(block)

        # Graph walker

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    @timethis
    def _make_function_prototype(self, arg_list: List[SimVariable], variable_kb):
        if self.function.prototype is not None:
            # do not overwrite an existing function prototype
            # if you want to re-generate the prototype, clear the existing one first
            return

        variables = variable_kb.variables[self.function.addr]
        func_args = [ ]
        for arg in arg_list:
            func_arg = None
            arg_ty = variables.get_variable_type(arg)
            if arg_ty is None:
                # determine type based on size
                if isinstance(arg, (SimRegisterVariable, SimStackVariable)):
                    if arg.size == 1:
                        func_arg = SimTypeChar()
                    elif arg.size == 2:
                        func_arg = SimTypeShort()
                    elif arg.size == 4:
                        func_arg = SimTypeInt()
                    elif arg.size == 8:
                        func_arg = SimTypeLongLong()
                    else:
                        l.warning("Unsupported argument size %d.", arg.size)
            else:
                func_arg = arg_ty

            func_args.append(func_arg)

        if self.function.calling_convention is not None and self.function.calling_convention.ret_val is None:
            returnty = SimTypeBottom(label="void")
        else:
            returnty = SimTypeInt()

        self.function.prototype = SimTypeFunction(func_args, returnty)

    @timethis
    def _recover_and_link_variables(self, ail_graph, arg_list):

        # variable recovery
        tmp_kb = KnowledgeBase(self.project)
        # remove existing variables for this function
        if tmp_kb.variables.has_function_manager(self.function.addr):
            l.warning("Removing existing variable recovery result for function %#x.", self.function.addr)
            del tmp_kb.variables[self.function.addr]
        # stack pointers have been removed at this point
        vr = self.project.analyses.VariableRecoveryFast(self.function,  # pylint:disable=unused-variable
                                                        func_graph=ail_graph, kb=tmp_kb, track_sp=False,
                                                        func_args=arg_list)
        # clean up existing types for this function
        tmp_kb.variables[self.function.addr].remove_types()
        # TODO: Type inference for global variables
        # run type inference
        try:
            tp = self.project.analyses.Typehoon(vr.type_constraints, kb=tmp_kb, var_mapping=vr.var_to_typevar)
            tp.update_variable_types(self.function.addr, vr.var_to_typevar)
        except Exception:  # pylint:disable=broad-except
            l.warning("Typehoon analysis failed. Variables will not have types. Please report to GitHub.",
                      exc_info=True)

        # Unify SSA variables
        tmp_kb.variables[self.function.addr].unify_variables()
        tmp_kb.variables[self.function.addr].assign_unified_variable_names(labels=self.kb.labels, reset=True)

        # Link variables to each statement
        for block in ail_graph.nodes():
            self._link_variables_on_block(block, tmp_kb)
        return tmp_kb

    def _link_variables_on_block(self, block, kb):
        """
        Link atoms (AIL expressions) in the given block to corresponding variables identified previously.

        :param ailment.Block block: The AIL block to work on.
        :return:                    None
        """

        variable_manager = kb.variables[self.function.addr]
        global_variables = kb.variables['global']

        for stmt_idx, stmt in enumerate(block.statements):
            stmt_type = type(stmt)
            if stmt_type is ailment.Stmt.Store:
                # find a memory variable
                mem_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, stmt)
                if len(mem_vars) == 1:
                    stmt.variable, stmt.offset = next(iter(mem_vars))
                else:
                    # check if the dest address is a variable
                    stmt: ailment.Stmt.Store
                    # special handling for constant addresses
                    if isinstance(stmt.addr, ailment.Expr.Const):
                        # global variable?
                        variables = global_variables.get_global_variables(stmt.addr.value)
                        if variables:
                            var = next(iter(variables))
                            stmt.variable = var
                            stmt.offset = 0
                    else:
                        self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt,
                                                     stmt.addr)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.data)

            elif stmt_type is ailment.Stmt.Assignment:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.dst)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.src)

            elif stmt_type is ailment.Stmt.ConditionalJump:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.condition)

            elif stmt_type is ailment.Stmt.Call:
                self._link_variables_on_call(variable_manager, global_variables, block, stmt_idx, stmt, is_expr=False)

            elif stmt_type is ailment.Stmt.Return:
                self._link_variables_on_return(variable_manager, global_variables, block, stmt_idx, stmt)

    def _link_variables_on_return(self, variable_manager, global_variables, block: ailment.Block, stmt_idx: int,
                                  stmt: ailment.Stmt.Return):
        if stmt.ret_exprs:
            for ret_expr in stmt.ret_exprs:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, ret_expr)

    def _link_variables_on_call(self, variable_manager, global_variables, block, stmt_idx, stmt, is_expr=False):
        if stmt.args:
            for arg in stmt.args:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt,
                                             arg)
        if not is_expr and stmt.ret_expr:
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt,
                                         stmt.ret_expr)

    def _link_variables_on_expr(self, variable_manager, global_variables, block, stmt_idx, stmt, expr):
        """
        Link atoms (AIL expressions) in the given expression to corresponding variables identified previously.

        :param variable_manager:    Variable manager of the function.
        :param ailment.Block block: AIL block.
        :param int stmt_idx:        ID of the statement.
        :param stmt:                The AIL statement that `expr` belongs to.
        :param expr:                The AIl expression to work on.
        :return:                    None
        """

        if type(expr) is ailment.Expr.Register:
            # find a register variable
            reg_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            # TODO: make sure it is the correct register we are looking for
            if len(reg_vars) == 1:
                reg_var, offset = next(iter(reg_vars))
                expr.variable = reg_var
                expr.variable_offset = offset

        elif type(expr) is ailment.Expr.Load:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) == 0:
                # this is a local variable
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.addr)
                if 'reference_variable' in expr.addr.tags and expr.addr.reference_variable is not None:
                    # copy over the variable to this expr since the variable on a constant is supposed to be a
                    # reference variable.
                    expr.variable = expr.addr.reference_variable
                    expr.variable_offset = expr.addr.reference_variable_offset
            else:
                if len(variables) > 1:
                    l.error("More than one variable are available for atom %s. Consider fixing it using phi nodes.",
                            expr
                            )
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset

        elif type(expr) is ailment.Expr.BinaryOp:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) == 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operands[0])
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operands[1])

        elif type(expr) is ailment.Expr.UnaryOp:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) == 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operands)

        elif type(expr) is ailment.Expr.Convert:
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operand)

        elif isinstance(expr, ailment.Expr.BasePointerOffset):
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) == 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset

        elif isinstance(expr, ailment.Expr.Const):
            # global variable?
            variables = global_variables.get_global_variables(expr.value)
            if variables:
                var = next(iter(variables))
                expr.tags['reference_variable'] = var
                expr.tags['reference_variable_offset'] = None

        elif isinstance(expr, ailment.Stmt.Call):
            self._link_variables_on_call(variable_manager, global_variables, block, stmt_idx, expr, is_expr=True)

    def _function_graph_to_ail_graph(self, func_graph, blocks_by_addr_and_size=None):

        if blocks_by_addr_and_size is None:
            blocks_by_addr_and_size = self._blocks_by_addr_and_size

        node_to_block_mapping = {}
        graph = networkx.DiGraph()

        for node in func_graph.nodes():
            ail_block = blocks_by_addr_and_size.get((node.addr, node.size), node)
            node_to_block_mapping[node] = ail_block

            if ail_block is not None:
                graph.add_node(ail_block)

        for src_node, dst_node, data in func_graph.edges(data=True):
            src = node_to_block_mapping[src_node]
            dst = node_to_block_mapping[dst_node]

            if dst is not None:
                graph.add_edge(src, dst, **data)

        return graph

    @staticmethod
    def _make_callsites_rd_observe_callback(ob_type, **kwargs):
        if ob_type != 'insn':
            return False
        stmt = kwargs.pop('stmt')
        op_type = kwargs.pop('op_type')
        return isinstance(stmt, ailment.Stmt.Call) and op_type == OP_BEFORE

    @staticmethod
    def _simplify_function_rd_observe_callback(ob_type, **kwargs):
        if ob_type != 'node':
            return False
        op_type = kwargs.pop('op_type')
        return op_type == OP_AFTER


register_analysis(Clinic, 'Clinic')
