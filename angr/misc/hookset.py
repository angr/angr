"""
These classes perform some python magic that we use to implement the nesting of exploration technique methods.
This process is formalized as a "hooking" of a python method - each exploration technique's methods "hooks" a method of
the same name on the simulation manager class.
"""


class HookSet:
    """
    A HookSet is a static class that provides the capability to apply many hooks to an object.
    """

    @staticmethod
    def install_hooks(target, **hooks):
        """
        Given the target `target`, apply the hooks given as keyword arguments to it.
        If any targeted method has already been hooked, the hooks will not be overridden but will instead be pushed
        into a list of pending hooks. The final behavior should be that all hooks call each other in a nested stack.

        :param target:  Any object. Its methods named as keys in `hooks` will be replaced by `HookedMethod` objects.
        :param hooks:   Any keywords will be interpreted as hooks to apply. Each method named will hooked with the
                        corresponding function value.
        """
        for name, hook in hooks.items():
            func = getattr(target, name)
            if not isinstance(func, HookedMethod):
                func = HookedMethod(func)
                setattr(target, name, func)
            func.pending.append(hook)

    @staticmethod
    def remove_hooks(target, **hooks):
        """
        Remove the given hooks from the given target.

        :param target:  The object from which to remove hooks. If all hooks are removed from a given method, the
                        HookedMethod object will be removed and replaced with the original function.
        :param hooks:   Any keywords will be interpreted as hooks to remove. You must provide the exact hook that was
                        applied so that it can it can be identified for removal among any other hooks.
        """
        for name, hook in hooks.items():
            hooked = getattr(target, name)
            if hook in hooked.pending:
                try:
                    hooked.pending.remove(hook)
                except ValueError as e:
                    raise ValueError(f"{target} is not hooked by {hook}") from e
            if not hooked.pending:
                setattr(target, name, hooked.func)

    @staticmethod
    def copy_hooks(source, target, domain):
        """
        Copy the hooks from source onto target.

        If the current callstack includes hooked methods from source, the already-called methods will not be included in
        the copy.

        ``domain`` is a list of names that might be hooked.
        """
        for name in domain:
            hooked = getattr(source, name)
            if isinstance(hooked, HookedMethod):
                setattr(target, name, hooked.copy_to(getattr(target, name)))


class HookedMethod:
    """
    HookedMethod is a callable object which provides a stack of nested hooks.

    :param func:    The bottom-most function which provides the original functionality that is being hooked

    :ivar func:     Same as the eponymous parameter
    :ivar pending:  The stack of hooks that have yet to be called. When this object is called, it will pop the last
                    function in this list and call it. The function should call this object again in order to request
                    the functionality of the original method, at which point the pop-dispatch mechanism will run
                    recursively until the stack is exhausted, at which point the original function will be called.
                    When the call returns, the hook will be restored to the stack.
    """

    def __init__(self, func):
        self.func = func
        self.pending = []

    def __repr__(self):
        return "<HookedMethod(%s.%s, %d pending)>" % (
            self.func.__self__.__class__.__name__,
            self.func.__name__,
            len(self.pending),
        )

    def __call__(self, *args, **kwargs):
        if self.pending:
            current_hook = self.pending.pop()
            try:
                result = current_hook(self.func.__self__, *args, **kwargs)
            finally:
                self.pending.append(current_hook)
            return result
        else:
            return self.func(*args, **kwargs)

    def copy_to(self, new_func):
        new_hooked = HookedMethod(new_func)
        new_hooked.pending = list(self.pending)
        return new_hooked
