
import logging

import networkx

from .. import Analysis, register_analysis
from ...codenode import BlockNode
from ..calling_convention import CallingConventionAnalysis

import ailment
import ailment.analyses


l = logging.getLogger('angr.analyses.clinic')


class Clinic(Analysis):
    """
    A Clinic deals with AILments.
    """
    def __init__(self, func):
        self.function = func

        self.graph = networkx.DiGraph()

        self._ail_manager = None
        self._blocks = { }

        # sanity checks
        if not self.kb.functions:
            l.warning('No function is available in kb.functions. It will lead to a suboptimal conversion result.')

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
            return self._blocks[(addr, size)]
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

        CallingConventionAnalysis.recover_calling_conventions(self.project)

        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        self._convert_all()

        self._recover_and_link_variables()

        self._simplify_all()

        self._update_graph()

        ri = self.project.analyses.RegionIdentifier(self.function, graph=self.graph)  # pylint:disable=unused-variable

        # print ri.region.dbg_print()


    def _convert_all(self):
        """

        :return:
        """

        for block_node in self.function.transition_graph.nodes():
            ail_block = self._convert(block_node)

            if type(ail_block) is ailment.Block:
                self._blocks[(block_node.addr, block_node.size)] = ail_block

    def _convert(self, block_node):
        """

        :param block_node:
        :return:
        """

        if not type(block_node) is BlockNode:
            return block_node

        block = self.project.factory.block(block_node.addr, block_node.size)

        ail_block = ailment.IRSBConverter.convert(block.vex, self._ail_manager)
        return ail_block

    def _simplify_all(self):
        """

        :return:
        """

        for key in self._blocks.keys():
            ail_block = self._blocks[key]
            simplified = self._simplify(ail_block)
            self._blocks[key] = simplified

    def _simplify(self, ail_block):

        simp = self.project.analyses.AILSimplifier(ail_block)

        csm = self.project.analyses.AILCallSiteMaker(simp.result_block)
        if csm.result_block:
            ail_block = csm.result_block
            simp = self.project.analyses.AILSimplifier(ail_block)

        return simp.result_block

    def _recover_and_link_variables(self):

        # variable recovery
        vr = self.project.analyses.VariableRecoveryFast(self.function, clinic=self, kb=self.kb)  # pylint:disable=unused-variable

        # TODO: The current mapping implementation is kinda hackish...

        for block in self._blocks.values():
            self._link_variables_on_block(block)

    def _link_variables_on_block(self, block):
        """

        :param block:
        :return:
        """

        var_man = self.kb.variables[self.function.addr]

        for stmt_idx, stmt in enumerate(block.statements):
            # I wish I could do functional programming in this method...
            stmt_type = type(stmt)
            if stmt_type is ailment.Stmt.Store:
                # find a memory variable
                mem_vars = var_man.find_variables_by_stmt(block.addr, stmt_idx, 'memory')
                if len(mem_vars) == 1:
                    stmt.variable = mem_vars[0][0]
                self._link_variables_on_expr(var_man, block, stmt_idx, stmt, stmt.data)

            elif stmt_type is ailment.Stmt.Assignment:
                self._link_variables_on_expr(var_man, block, stmt_idx, stmt, stmt.dst)
                self._link_variables_on_expr(var_man, block, stmt_idx, stmt, stmt.src)

    def _link_variables_on_expr(self, variable_manager, block, stmt_idx, stmt, expr):

        # TODO: Make it recursive

        if type(expr) is ailment.Expr.Register:
            # find a register variable
            reg_vars = variable_manager.find_variables_by_stmt(block.addr, stmt_idx, 'register')
            # TODO: make sure it is the correct register we are looking for
            if len(reg_vars) == 1:
                reg_var = reg_vars[0][0]
                expr.variable = reg_var

        elif type(expr) is ailment.Expr.Load:
            # self._link_variables_on_expr(variable_manager, block, stmt_idx, stmt, expr.addr)
            pass

        elif type(expr) is ailment.Expr.BinaryOp:

            self._link_variables_on_expr(variable_manager, block, stmt_idx, stmt, expr.operands[0])
            self._link_variables_on_expr(variable_manager, block, stmt_idx, stmt, expr.operands[1])

    def _update_graph(self):

        node_to_block_mapping = {}

        for node in self.function.transition_graph.nodes():
            ail_block = self._blocks.get((node.addr, node.size), node)
            node_to_block_mapping[node] = ail_block

            self.graph.add_node(ail_block)

        for src_node, dst_node, data in self.function.transition_graph.edges(data=True):
            src = node_to_block_mapping[src_node]
            dst = node_to_block_mapping[dst_node]

            self.graph.add_edge(src, dst, **data)


register_analysis(Clinic, 'Clinic')
