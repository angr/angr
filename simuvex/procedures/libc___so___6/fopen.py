import simuvex
import symexec

######################################
# fopen
######################################

def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    return {
        "r"  : simuvex.Flags.O_RDONLY,
        "r+" : simuvex.Flags.O_RDWR,
        "w"  : simuvex.Flags.O_WRTONLY | simuvex.Flags.O_CREAT,
        "w+" : simuvex.Flags.O_RDWR | simuvex.Flags.O_CREAT,
        "a"  : simuvex.Flags.O_WRTONLY | simuvex.Flags.O_CREAT | simuvex.Flags.O_APPEND,
        "a+" : simuvex.Flags.O_RDWR | simuvex.Flags.O_CREAT | simuvex.Flags.O_APPEND
        }[mode]

def expr_to_ascii(expr):
    text = ""
    for i in reversed(range(expr.size() / 8)):
        l = 8 * i
        cod = symexec.simplify_expression(symexec.Extract(l + 7, l, expr)).as_long()
        text += str(unichr(cod))
    return text


class fopen(simuvex.SimProcedure):
    def __init__(self):
        # TODO: Symbolic path and errors
        plugin = self.state.get_plugin('posix')
        p_addr = self.get_arg_expr(0)
        m_addr = self.get_arg_expr(1)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        p_strlen = strlen(self.state, inline=True, arguments=[p_addr])
        m_strlen = strlen(self.state, inline=True, arguments=[m_addr])
        p_expr = self.state.mem_expr(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        m_expr = self.state.mem_expr(m_addr, m_strlen.max_null_index, endness='Iend_BE')
        path = expr_to_ascii(p_expr)
        mode = expr_to_ascii(m_expr)

        fd = plugin.open(path, mode_to_flag(mode))
        # TODO: handle append
        self.exit_return(simuvex.SimValue(fd).expr)
