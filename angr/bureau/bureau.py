import threading
import logging
from typing import List, TYPE_CHECKING

import zmq

from .messages import MessageBase, InvokeSyscall, SyscallReturn, RetrieveMemory, RetrieveMemoryReturn, SyncMemory, \
    RetrieveMemoryReturnResult

if TYPE_CHECKING:
    from angr import SimState
    from angr.calling_conventions import SimCCSyscall


_l = logging.getLogger(name=__name__)


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

    def invoke_syscall(self, state: 'SimState', num: int, args: List, syscall_cc: 'SimCCSyscall'):
        self.states[0] = state

        msg = InvokeSyscall(num, args)
        _l.debug("Sending %r.", msg)

        # wait until the socket is ready
        _l.debug("invoke_syscall(): Waiting for the socket to become ready.")
        self.zmq_sessions[0].event.wait()
        _l.debug("invoke_syscall(): Socket is ready.")
        self.zmq_sessions[0].socket.send(msg.serialize())

        # expect a SyscallReturn or a RetrieveMemory
        while True:
            msg = self.zmq_sessions[0].socket.recv()
            ret = MessageBase.unserialize(msg)
            _l.debug("Got a message: %r", ret)

            if isinstance(ret, SyscallReturn):
                # syscall execution completes
                syscall_cc.set_return_val(state, ret.retval)
                break
            elif isinstance(ret, RetrieveMemory):
                # the agent is asking for memory data
                state = self.states[0]
                data = state.memory.load(ret.addr, ret.size)
                if state.solver.symbolic(data):
                    _l.debug("Data is symbolic. Cannot retrieve memory. Abort.")
                    r = RetrieveMemoryReturn(RetrieveMemoryReturnResult.ABORT, None)
                else:
                    _l.debug("Send concrete data back to the syscall agent.")
                    r = RetrieveMemoryReturn(RetrieveMemoryReturnResult.OK, state.solver.eval(data, cast_to=bytes))
                self.zmq_sessions[0].socket.send(r.serialize())
            elif isinstance(ret, SyncMemory):
                raise NotImplementedError("SyncMemory is not implemented yet.")

        assert isinstance(ret, SyscallReturn)

        self.states[0] = None

        return state
