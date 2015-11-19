import logging

from ..analysis import Analysis, register_analysis
from networkx import DiGraph

l = logging.getLogger(name="angr.analyses.dfg")

class DFG(Analysis):
    def __init__(self, cfg=None, annocfg=None):
        """
        Build a Data Flow Grah (DFG) for every basic block of a CFG

        :param cfg: A CFG used to get all the basic blocks
        :param annocfg: An AnnotatedCFG built from a backward slice used to only build the DFG on the whitelisted statements
        """
        if cfg is None:
            self._cfg = self.project.analyses.CFG()
        else:
            self._cfg = cfg
        self._annocfg = annocfg

        self.dfgs = self._construct()

    def _need_to_ignore(self, addr, stmt, stmt_idx):
        if self._annocfg is not None:
            whitelist = self._annocfg.get_whitelisted_statements(addr)
            if whitelist is False or (whitelist is not None and stmt_idx not in whitelist):
                return True
        if stmt.tag == 'Ist_IMark' or stmt.tag == 'Ist_AbiHint' or stmt.tag == 'Ist_Exit':
            return True
        elif stmt.tag == 'Ist_Put':
            arch = self.project.arch
            if stmt.offset in arch.register_names:
                if stmt.offset == arch.ip_offset:
                    return True
        return False

    def _construct(self):
        """
        We want to build the type of DFG that's used in "Automated Ident. of Crypto
        Primitives in Binary Code with Data Flow Graph Isomorphisms." Unlike that
        paper, however, we're building it on Vex IR instead of assembly instructions.
        """
        cfg = self._cfg
        p = self.project
        dfgs = {}
        l.debug("Building Vex DFG...")

        for node in cfg.nodes():
            try:
                if node.simprocedure_name == None:
                    irsb = p.factory.block(node.addr).vex
                else:
                    continue
            except Exception as e:
                l.debug(e)
                continue
            tmpsnodes = {}
            storesnodes = {}
            putsnodes = {}
            statements = irsb.statements
            dfg = DiGraph()

            for stmt_idx, stmt in enumerate(statements):
                # We want to skip over certain types, such as Imarks
                if self._need_to_ignore(node.addr, stmt, stmt_idx):
                    continue

                # break statement down into sub-expressions
                exprs = stmt.expressions
                stmt_node = stmt
                dfg.add_node(stmt)

                if stmt.tag == 'Ist_WrTmp':
                    tmpsnodes[stmt.tmp] = stmt_node
                    if exprs[0].tag == 'Iex_Binop':
                        if exprs[1].tag == 'Iex_RdTmp':
                            dfg.add_edge(tmpsnodes[exprs[1].tmp], stmt_node)
                        else:
                            dfg.add_edge(exprs[1], stmt_node)
                        if exprs[2].tag == 'Iex_RdTmp':
                            dfg.add_edge(tmpsnodes[exprs[2].tmp], stmt_node)
                        else:
                            dfg.add_edge(exprs[2], stmt_node)

                    elif exprs[0].tag == 'Iex_Unop':
                        if exprs[1].tag == 'Iex_RdTmp':
                            dfg.remove_node(stmt_node)
                            tmpsnodes[stmt.tmp] = tmpsnodes[exprs[1].tmp]
                        else:
                            dfg.remove_node(stmt_node)
                            #dfg.add_node(exprs[0])
                            tmpsnodes[stmt.tmp] = exprs[1]

                    elif exprs[0].tag == 'Iex_RdTmp':
                        tmpsnodes[stmt.tmp] = tmpsnodes[exprs[0].tmp]

                    elif exprs[0].tag == 'Iex_Get':
                        if putsnodes.has_key(exprs[0].offset):
                            dfg.add_edge(putsnodes[exprs[0].offset], stmt_node)
                        if len(exprs) > 1 and exprs[1].tag == "Iex_RdTmp":
                            dfg.add_edge(tmpsnodes[exprs[1].tmp], stmt_node)
                        elif len(exprs) > 1:
                            dfg.add_edge(exprs[1], stmt_node)

                    elif exprs[0].tag == 'Iex_Load':
                        if exprs[1].tag == 'Iex_RdTmp':
                            dfg.add_edge(tmpsnodes[exprs[1].tmp], stmt_node)
                        else:
                            dfg.add_edge(exprs[1], stmt_node)

                    else:
                        # Take a guess by assuming exprs[0] is the op and any other expressions are args
                        for e in exprs[1:]:
                            if e.tag == 'Iex_RdTmp':
                                dfg.add_edge(tmpsnodes[e.tmp], stmt_node)
                            else:
                                dfg.add_edge(e, stmt_node)

                elif stmt.tag == 'Ist_Store':
                    if exprs[0].tag == 'Iex_RdTmp':
                        dfg.add_edge(tmpsnodes[exprs[0].tmp], stmt_node)

                    elif exprs[0].tag == 'Iex_Const':
                        dfg.add_edge(exprs[0], stmt_node)

                    if exprs[1].tag == 'Iex_RdTmp':
                        dfg.add_edge(tmpsnodes[exprs[1].tmp], stmt_node)
                    else:
                        dfg.add_edge(exprs[1], stmt_node)

                elif stmt.tag == 'Ist_Put':
                    if exprs[0].tag == 'Iex_RdTmp':
                        dfg.add_edge(tmpsnodes[exprs[0].tmp], stmt_node)
                    elif exprs[0].tag == 'Iex_Const':
                        dfg.add_edge(exprs[0], stmt_node)
                    putsnodes[stmt.offset] = stmt_node

                elif stmt.tag == 'Ist_Exit':
                    if exprs[0].tag == 'Iex_RdTmp':
                        dfg.add_edge(tmpsnodes[exprs[0].tmp], stmt_node)

                elif stmt.tag == 'Ist_Dirty':
                    tmpsnodes[stmt.tmp] = stmt_node
                elif stmt.tag == 'Ist_CAS':
                    tmpsnodes[stmt.oldLo] = stmt_node

                else:
                    if hasattr(stmt, 'tmp'):
                        tmpsnodes[stmt.tag] = stmt_node
                    for e in stmt.expressions:
                        if e.tag == 'Iex_RdTmp':
                            dfg.add_edge(tmpsnodes[e.tmp], stmt_node)
                        else:
                            dfg.add_edge(e, stmt_node)

            for vtx in dfg.nodes():
                if dfg.degree(vtx) == 0:
                    dfg.remove_node(vtx)

            dfgs[node.addr] = dfg
        return dfgs

register_analysis(DFG, 'DFG')
