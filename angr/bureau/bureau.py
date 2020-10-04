import threading
from typing import List

import zmq

from .messages import MessageBase, InvokeSyscall, SyscallReturn


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

        # expect a SyscallReturn
        msg = self.zmq_sessions[0].socket.recv()
        ret = MessageBase.unserialize(msg)

        assert isinstance(ret, SyscallReturn)

        self.states[0] = None
