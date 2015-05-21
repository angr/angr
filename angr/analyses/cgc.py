from ..analysis import Analysis

import simuvex

class CGC(Analysis):
    '''
    This analysis attempts to find memory corruption vulnerabilities in CGC stuff.
    '''

    @staticmethod
    def check_path(p):
        if not p.reachable:
            return False

        for a in reversed(p.events):
            if a.type == 'cgc_checkpoint':
                break

            if isinstance(a, simuvex.SimActionData) and a.type == 'mem':
                addr = p.state.se.any_int(a.addr.ast)
                tb = (addr >> 24)
                if tb != 0xff and tb != 0xc and tb != 0x08:
                    return True

        if CGC.check_expr(p.state.ip) and len(p.state.se.any_n_int(p.state.ip, 257)) > 256:
            return True

        p.events.append(simuvex.SimEvent(p.state, 'cgc_checkpoint'))
        return False

    @staticmethod
    def check_expr(expr):
        for v in expr.variables:
            if 'file' in v:
                return True

        return False

    def __init__(self):
        # make a CGC state
        s = self._p.initial_state()
        s.get_plugin('cgc')
        self.e = self._p.surveyors.Explorer(start=self._p.exit_to(self._p.entry, state=s), find=self.check_for_eip_control, enable_veritesting=True)

        self.e.run()
        self.vuln_path = (self.e.found + self.e.errored)[0]

        self.pov = """<?xml version="1.0" standalone="no" ?>
<!DOCTYPE pov SYSTEM "/usr/share/cgc-docs/replay.dtd">
<pov>
    <cbid>service</cbid>
        <replay>
"""

        s = self.vuln_path.state
        for a in self.vuln_path.events:
            if isinstance(a, simuvex.SimActionData) and a.type == 'file' and s.se.solution(a.fd.ast, 1):
                max_size = s.se.max_int(a.size.ast)
                sval = s.se.any_str(a.data.ast)[:max_size]
                self.pov += "        <read><length>%d</length><match><data>%s</data></match></read>\n" % (max_size, repr(sval)[1:-1])

            elif isinstance(a, simuvex.SimActionData) and a.type == 'file' and s.se.solution(a.fd.ast, 0):
                max_size = s.se.max_int(a.size.ast)
                sval = s.se.any_str(a.data.ast)[:max_size]
                self.pov += "        <write>\n            <data>%s</data>\n        </write>\n" % repr(sval)[1:-1]

        self.pov += "</replay>\n</pov>\n"
