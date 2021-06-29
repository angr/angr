from .variable_manager import VariableManagerInternal


class VariableManagerParser:
    """
    VariableManagerParser serializes and unserializes VariableManagerInternal instances.
    """

    @staticmethod
    def serialize(internal: VariableManagerInternal):
        raise NotImplementedError()

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None, all_func_addrs=None) -> VariableManagerInternal:
        raise NotImplementedError()
