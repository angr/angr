
from functools import wraps
from typing import Set, Optional, List

try:
    import binsync
    from binsync.client import Client
    from binsync.data.stack_variable import StackVariable, StackOffsetType
    binsync_available = True
except ImportError:
    binsync_available = False

from ... import knowledge_plugins
from ...sim_variable import SimStackVariable
from ...knowledge_base.knowledge_base import KnowledgeBase
from ..plugin import KnowledgeBasePlugin
from ..variables.variable_manager import VariableManagerInternal


def last_push(f):
    """
    Once a push function has been executed, perform an update on the last push time,
    last push function, and the local function name for the master user.
    """

    @wraps(f)
    def set_last_push(self, *args, **kwargs):

        def parse_push_args_func_addr(push_args):
            arg = args[0]
            func_addr = None
            # push func
            if isinstance(arg, knowledge_plugins.Function):
                func_addr = arg.addr

            # push many [comments, stack_vars]
            elif isinstance(arg, list):
                if isinstance(arg[0], SimStackVariable):
                    func_addr = push_args[1].func_addr
                elif isinstance(arg[0], binsync.data.Comment):
                    func_addr = arg[0].func_addr

            # push [comment]
            elif isinstance(arg, int):
                func_addr = self._get_func_addr_from_addr(ard)

            return func_addr

        attr_func_addr = parse_push_args_func_addr(args[0])
        attr_func_addr = attr_func_addr if attr_func_addr else -1

        last_push_time = int(time.time())
        last_push_func = attr_func_addr
        func_name = self._kb.functions[attr_func_addr].name if self._kb.functions[attr_func_addr] else ""

        f(self, *args, **kwargs)
        self._client.last_push(last_push_func, last_push_time, func_name)

    return set_last_push


def make_state(f):
    """
    Build a writeable State instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """

    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            state = self._client.get_state(user=user)
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
            state.save()
            return r
        else:
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
            return r

    return state_check


def make_ro_state(f):
    """
    Build a read-only State instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """

    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            state = self._client.get_state(user=user)
        kwargs['state'] = state
        kwargs['user'] = user
        return f(self, *args, **kwargs)

    return state_check


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if self._client is None:
            raise ValueError("Please initialize SyncController by calling initialize(client).")
        return f(self, *args, **kwargs)
    return initcheck


class SyncController(KnowledgeBasePlugin):
    """
    SyncController interfaces with a binsync client to push changes upwards and pull changes downwards.

    :ivar binsync.Client _client:   The binsync client.
    """
    def __init__(self, kb):
        super().__init__()

        self._kb: KnowledgeBasePlugin = kb
        self._client: Optional[binsync.client.Client] = None

    #
    # Public methods
    #

    def connect(self, user, path, bin_hash="", init_repo=False, remote_url=None, ssh_agent_pid=None, ssh_auth_sock=None):
        self._client = Client(user, path, bin_hash,
                              init_repo=init_repo,
                              ssh_agent_pid=ssh_agent_pid,
                              ssh_auth_sock=ssh_auth_sock)

    @property
    def connected(self):
        return self._client is not None

    def commit(self):
        self._client.save_state()

    def update(self):
        self._client.update()

    def copy(self):
        raise NotImplementedError

    @init_checker
    def users(self):
        return self._client.users()

    @init_checker
    def status(self):
        return self._client.status()

    def tally(self, users=None):
        return self._client.tally(users=users)

    #
    # Fillers
    #

    def fill_function(self, func, user=None):
        """
        Grab all relevant information from the specified user and fill the @func.

        :param Function func:   The Function object to work on.
        :param str user:        Name of the user where we are going to pull information from. If None, information will
                                be pulled from the current user.
        :return:                None
        """

        _func = self.pull_function(func.addr, user=user)  # type: binsync.data.Function
        if _func is None:
            # the function does not exist for that user's state
            return
        func.name = _func.name

        # comments
        for block in func.blocks:
            for ins_addr in block.instruction_addrs:
                _comment = self.pull_comment(ins_addr, user=user)
                if _comment is not None:
                    self._kb.comments[ins_addr] = _comment

        # stack vars done in angr-management

    #
    # Pushers
    #

    @init_checker
    @make_state
    @last_push
    def push_function(self, func: knowledge_plugins.Function, user=None, state=None):
        """
        Push a function upwards.

        :param Function func:   The angr Function object to push upwards.
        :return:                True if updates are made. False otherwise.
        :rtype:                 bool
        """

        _func = binsync.data.Function(func.addr, name=func.name, notes=None)
        return state.set_function(_func)

    @init_checker
    @make_state
    @last_push
    def push_comment(self, addr, comment, decompiled=False, user=None, state=None):
        """
        Push a comment at a certain address upwards.

        :param int addr:    Address of the comment.
        :param str comment: The comment itself.
        :return:            bool
        """
        func_addr = self._get_func_addr_from_addr(addr)
        func_addr = func_addr if func_addr else -1

        sync_cmt = binsync.data.Comment(func_addr, addr, comment, decompiled)

        return state.set_comment(sync_cmt)

    @init_checker
    @make_state
    @last_push
    def push_comments(self, comments: List[binsync.data.Comment], user=None, state=None):
        """
        Push a bunch of comments upwards.

        :param list comments:   A list of BinSync Comments
        :return:                bool
        """

        r = True
        for cmt in comments:
            r &= state.set_comment(cmt)
        return r

    @init_checker
    @make_state
    @last_push
    def push_stack_variables(self, stack_variables: List[SimStackVariable], var_manager: VariableManagerInternal,
                             user=None, state=None):
        """

        :param stack_variables:
        :param var_manager:
        :return:
        """
        r = True
        for var in stack_variables:
            guessed_var_type = var_manager.get_variable_type(var)
            var_type = guessed_var_type if guessed_var_type else "BOT"

            # construct a StackVariable for each SimStackVariable
            sync_stack_var = StackVariable(var.offset, StackOffsetType.ANGR, var.name,
                                           var_type, var.size, var_manager.func_addr)

            r &= state.set_stack_variable(var_manager.func_addr, var.offset, sync_stack_var)

        # return true only if all pushed worked
        return r

    #
    # Pullers
    #

    @init_checker
    @make_ro_state
    def pull_function(self, addr, user=None, state=None) -> binsync.data.Function:
        """
        Pull a function downwards.

        :param int addr:    Address of the function.
        :param str user:    Name of the user.
        :return:            The binsync.data.Function object if pulling succeeds, or None if pulling fails.
        :rtype:             binsync.data.Function
        """

        func_addr = self._get_func_addr_from_addr(addr)
        func_addr = func_addr if func_addr else -1

        try:
            func = state.get_function(func_addr)
            return func
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_comment(self, addr, user=None, state=None) -> binsync.data.Comment:
        """
        Pull a comment downwards.

        :param int addr:    Address of the comment.
        :param str user:    Name of the user.
        :return:            The comment it self, or None if there is no comment.
        :rtype:             str or None
        """

        func_addr = self._get_func_addr_from_addr(addr)
        func_addr = func_addr if func_addr else -1
        try:
            comment = state.get_comment(func_addr, addr)
            return comment
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_comments(self, start_addr, end_addr=None, user=None):
        """
        Pull comments downwards.

        :param int start_addr:  Where we want to pull comments.
        :param int end_addr:    Where we want to stop pulling comments (exclusive).
        :return:                An iterator.
        :rtype:                 Iterable
        """

        return state.get_comments(start_addr, end_addr=end_addr)

    @init_checker
    @make_ro_state
    def pull_patches(self, user=None, state=None):
        """
        Pull patches.

        :param str user:    Name of the user to patches from.
        :return:            An iterator
        :rtype:             Iterable
        """

        return state.get_state(user=user).get_patches()

    @init_checker
    @make_ro_state
    def pull_stack_variables(self, func_addr, user=None, state=None):
        """
        Pull stack variables from a function.

        @param func_addr:   Function address to pull from
        @param user:
        @param state:
        @return:
        """
        try:
            stack_vars = state.get_stack_variables(func_addr)
        except KeyError:
            stack_vars = {}

        return stack_vars

    #
    #   Utils
    #

    def _get_func_addr_from_addr(self, addr):
        try:
            func_addr = self._kb.cfgs.get_most_accurate().get_any_node(addr).function_address
        except AttributeError:
            func_addr = None

        return func_addr


if binsync_available:
    KnowledgeBasePlugin.register_default("sync", SyncController)
