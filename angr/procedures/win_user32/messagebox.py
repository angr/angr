import angr

class MessageBoxA(angr.SimProcedure):
    def run(self, hWnd, lpText, lpCaption, uType):
        text = self.state.mem[lpText].string.concrete
        if not self.state.solver.is_true(lpCaption == 0):
            caption = self.state.mem[lpCaption].string.concrete
        else:
            caption = 'Error'
        self.state.history.add_event('message_box', text=text, caption=caption)