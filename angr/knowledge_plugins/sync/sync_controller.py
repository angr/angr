
from functools import wraps
from typing import Optional, List
import time

try:
    import binsync
    from binsync.client import Client
    from binsync.data.stack_variable import StackVariable, StackOffsetType
    binsync_available = True
except ImportError:
    binsync_available = False

from ... import knowledge_plugins
from ...knowledge_plugins.plugin import KnowledgeBasePlugin
from ...sim_variable import SimStackVariable
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
                func_addr = arg #self.get_func_addr_from_addr(arg)

            return func_addr

        attr_func_addr = parse_push_args_func_addr(args)
        attr_func_addr = attr_func_addr if attr_func_addr else -1

        last_push_time = int(time.time())
        last_push_func = attr_func_addr
        #func_name = self._kb.functions[attr_func_addr].name if attr_func_addr in self._kb.functions else ""

        f(self, *args, **kwargs)
        self.client.last_push(last_push_func, last_push_time)

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
            state = self.client.get_state(user=user)
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
            state = self.client.get_state(user=user)
        kwargs['state'] = state
        kwargs['user'] = user
        return f(self, *args, **kwargs)

    return state_check


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if self.client is None:
            raise ValueError("Please initialize SyncController by calling initialize(client).")
        return f(self, *args, **kwargs)
    return initcheck


class SyncController(KnowledgeBasePlugin):
    """
    SyncController interfaces with a binsync client to push changes upwards and pull changes downwards.

    :ivar binsync.Client client:   The binsync client.
    """
    def __init__(self, kb):
        super().__init__()

        self._kb: KnowledgeBasePlugin = kb
        self.client: Optional['binsync.client.Client'] = None

    #
    # Public methods
    #

    def connect(self, user, path,
                bin_hash="", init_repo=False, ssh_agent_pid=None, ssh_auth_sock=None, remote_url=None):
        self.client = Client(user, path, bin_hash,
                             init_repo=init_repo,
                             ssh_agent_pid=ssh_agent_pid,
                             ssh_auth_sock=ssh_auth_sock,
                             remote_url=remote_url)

    @property
    def connected(self):
        return self.client is not None

    def commit(self):
        self.client.save_state()

    def update(self):
        self.client.update()

    def copy(self):
        raise NotImplementedError

    def pull(self):
        return self.client.pull()

    @property
    def has_remote(self):
        return self.client.has_remote

    @init_checker
    def users(self):
        return self.client.users()

    @init_checker
    def status(self):
        return self.client.status()

    def tally(self, users=None):
        return self.client.tally(users=users)

    #
    # Pushers
    #

    @init_checker
    @make_state
    @last_push
    # pylint:disable=unused-argument,no-self-use
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
    # pylint:disable=unused-argument,no-self-use
    def push_comment(self, func_addr, addr, comment, decompiled=False, user=None, state=None):
        #func_addr = self.get_func_addr_from_addr(addr)
        #func_addr = func_addr if func_addr else -1
        sync_cmt = binsync.data.Comment(func_addr, addr, comment, decompiled)

        return state.set_comment(sync_cmt)

    @init_checker
    @make_state
    @last_push
    # pylint:disable=unused-argument,no-self-use
    def push_comments(self, comments: List['binsync.data.Comment'], user=None, state=None):
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
    # pylint:disable=unused-argument,no-self-use
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

    @init_checker
    @make_state
    @last_push
    # pylint:disable=unused-argument,no-self-use
    def push_stack_variable(self, func_addr, offset, name, type_, size_, user=None, state=None):
        sync_var = StackVariable(offset, StackOffsetType.ANGR, name, type_, size_, func_addr)
        return state.set_stack_variable(func_addr, offset, sync_var)

    #
    # Pullers
    #

    @init_checker
    @make_ro_state
    # pylint:disable=unused-argument
    def pull_function(self, addr, user=None, state=None) -> Optional['binsync.data.Function']:
        """
        Pull a function downwards.

        :param int addr:    Address of the function.
        :param str user:    Name of the user.
        :return:            The binsync.data.Function object if pulling succeeds, or None if pulling fails.
        """

        func_addr = self.get_func_addr_from_addr(addr)
        func_addr = func_addr if func_addr else -1

        try:
            func = state.get_function(func_addr)
            return func
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    # pylint:disable=unused-argument
    def pull_comment(self, addr, user=None, state=None) -> Optional['binsync.data.Comment']:
        """
        Pull a comment downwards.

        :param int addr:    Address of the comment.
        :param str user:    Name of the user.
        :return:            a Comment object from BinSync, or None
        """

        func_addr = self.get_func_addr_from_addr(addr)
        func_addr = func_addr if func_addr else -1
        try:
            comment = state.get_comment(func_addr, addr)
            return comment
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    # pylint:disable=unused-argument,no-self-use
    def pull_comments(self, func_addr, user=None, state=None):
        """
        Pull comments downwards.

        :param int start_addr:  Where we want to pull comments.
        :param int end_addr:    Where we want to stop pulling comments (exclusive).
        :return:                An iterator.
        :rtype:                 Iterable
        """
        try:
            comments = state.get_comments(func_addr)
            return comments
        except KeyError:
            return {}

    @init_checker
    @make_ro_state
    # pylint:disable=unused-argument,no-self-use
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
    # pylint:disable=unused-argument,no-self-use
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

    def get_func_addr_from_addr(self, addr):
        try:
            func_addr = self._kb.cfgs.get_most_accurate().get_any_node(addr, anyaddr=True).function_address
        except AttributeError:
            func_addr = None

        return func_addr


if binsync_available:
    KnowledgeBasePlugin.register_default("sync", SyncController)
