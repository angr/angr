import angr

class MessageBoxA(angr.SimProcedure):
    def run(self, hWnd, lpText, lpCaption, uType):
        text = self.extract(lpText)
        if not self.state.solver.is_true(lpCaption == 0):
            caption = self.extract(lpCaption)
        else:
            caption = 'Error'
        self.state.history.add_event('message_box', text=text, caption=caption)

    def extract(self, addr):
        return self.state.mem[addr].string.concrete

class MessageBoxExA(angr.SimProcedure):
    def run(self, hWnd, lpText, lpCaption, uType, wLanguageId):
        super(MessageBoxExA, self).run(hWnd, lpText, lpCaption, uType)

class MessageBoxW(MessageBoxA):
    def extract(self, addr):
        return self.state.mem[addr].wstring.concrete

class MessageBoxExW(MessageBoxW, MessageBoxExA):
    pass