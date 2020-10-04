import threading
from typing import List

import zmq

from .messages import MessageBase, InvokeSyscall, SyscallReturn, RetrieveMemory, RetrieveMemoryReturn, \
    RetrieveMemoryReturnResult


class Session:
    def __init__(self, socket):
        self.socket = socket
        self.event = threading.Event()


class Bureau:
    def __init__(self, project):
        self.project = project
        self.states: List = [None] * 10  # TODO: Implement sessions so we support multiple agents

        # zeromq
        self.zmq_context = zmq.Context()
        self.zmq_sessions = [ ]
        for i in range(10):
            socket = self.zmq_context.socket(zmq.REP)
            socket.bind("tcp://*:%d" % (5555 + i))
            self.zmq_sessions.append(Session(socket))

        # handler thread
        self.serve_thread = threading.Thread(target=self.serve, daemon=True)
        self.serve_thread.start()

    def serve(self):
        tmp = self.zmq_sessions[0].socket.recv()
        assert tmp  # non-empty
        self.zmq_sessions[0].event.set()

    def invoke_syscall(self, state, num: int, args: List):
        self.states[0] = state

        msg = InvokeSyscall(num, args)

        # wait until the socket is ready
        print("waiting...")
        self.zmq_sessions[0].event.wait()
        print("OHHHH")
        self.zmq_sessions[0].socket.send(msg.serialize())

        # expect a SyscallReturn or a RetrieveMemory
        print("Enter...")
        while True:
            msg = self.zmq_sessions[0].socket.recv()
            ret = MessageBase.unserialize(msg)

            print(ret)

            if isinstance(ret, SyscallReturn):
                # syscall execution completes
                break
            elif isinstance(ret, RetrieveMemory):
                # the agent is asking for memory data
                state = self.states[0]
                data = state.memory.load(ret.addr, ret.size)
                if state.solver.symbolic(data):
                    r = RetrieveMemoryReturn(RetrieveMemoryReturnResult.ABORT, None)
                else:
                    r = RetrieveMemoryReturn(RetrieveMemoryReturnResult.OK, state.solver.eval(data, cast_to=bytes))
                self.zmq_sessions[0].socket.send(r.serialize())

        assert isinstance(ret, SyscallReturn)

        self.states[0] = None

        return state
