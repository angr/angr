from ..analysis import Analysis
from ..variableseekr import StackVariable

import simuvex

class CGC(Analysis):
    '''
    This analysis attempts to find memory corruption vulnerabilities in CGC stuff.
    '''

    @staticmethod
    def check_state(st):
        for a in reversed(st.log.old_events):
            if a.type == 'cgc_checkpoint':
                break

            if isinstance(a, simuvex.SimActionData) and a.type == 'mem':
                addr = st.se.any_int(a.objects['addr'].ast)
                tb = (addr >> 24)
                if tb != 0xff and tb != 0xc and tb != 0x08:
                    return True

        st.log.add_event('cgc_checkpoint')
        st.log.old_events += st.log.new_events
        st.log.new_events = [ ]
        return False

    @staticmethod
    def check_expr(expr):
        for v in expr.variables:
            if 'file' in v:
                return True

        return False

    def check_path(self, p):
        for e in p.exits():
            if not e.reachable():
                continue

            if self.check_state(e.state):
                return True

            if self.check_expr(e.target) and not e.is_unique() and len(e.split()) == 0:
                return True

        return False

    def __init__(self):
        # make a CGC state
        s = self._p.initial_state()
        s.get_plugin('cgc')
        self.e = self._p.surveyors.Explorer(start=self._p.exit_to(self._p.entry, state=s), find=self.check_for_eip_control, enable_veritesting=True)

        self.e.run()
        self.vuln_path = self.e.found[0]

        self.pov = """<?xml version="1.0" standalone="no" ?>
<!DOCTYPE pov SYSTEM "/usr/share/cgc-docs/replay.dtd">
<pov>
    <cbid>service</cbid>
        <replay>
"""

        s = self.vuln_path.last_initial_state
        for a in s.log.old_events:
            if isinstance(a, simuvex.SimActionData) and a.type == 'file' and s.se.solution(a.objects['fd'].ast, 1):
                max_size = s.se.max_int(a.objects['size'].ast)
                sval = s.se.any_str(a.objects['data'].ast)[:max_size]
                self.pov += "        <read><length>%d</length><match><data>%s</data></match></read>\n" % (max_size, repr(sval)[1:-1])

            elif isinstance(a, simuvex.SimActionData) and a.type == 'file' and s.se.solution(a.objects['fd'].ast, 0):
                max_size = s.se.max_int(a.objects['size'].ast)
                sval = s.se.any_str(a.objects['data'].ast)[:max_size]
                self.pov += "        <write>\n            <data>%s</data>\n        </write>\n" % repr(sval)[1:-1]

        self.pov += "</replay>\n</pov>\n"
