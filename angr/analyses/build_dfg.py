from networkx import DiGraph

def build_dfg(p, cfg):
    """
    We want to build the type of DFG that's used in "Automated Ident. of Crypto
    Primitives in Binary Code with Data Flow Graph Isomorphisms." Unlike that
    paper, however, we're building it on Vex IR instead of assembly instructions.
    """
    dfgs = {}
    print "Building Vex DFG..."

    for node in cfg.nodes():
        try:
            if node.simprocedure_name == None:
                irsb = p.factory.block(node.addr).vex
            else:
                continue
        except Exception as e:
            print e
            continue
        tmpsnodes = {}
        storesnodes = {}
        putsnodes = {}
        statements = irsb.statements
        dfg = DiGraph()

        for stmt in statements:
            # We want to skip over certain types, such as Imarks
            if stmt.tag == 'Ist_IMark' or stmt.tag == 'Ist_AbiHint':
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
                        try:
                            tmpsnodes[stmt.tmp] = tmpsnodes[exprs[1].tmp]
                        except Exception as e:
                            print e
                            ipdb.set_trace()
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
                    if stmt.offset == 184:
                        continue
                    else:
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