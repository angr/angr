
import logging

from ..sim_type import parse_file

l = logging.getLogger('angr.prototypes.sim_prototypes')


class SimPrototypes(object):
    """
    A storage of function prototypes.
    """

    def __init__(self, library_name, alternative_names=None):
        self.library_name = library_name
        self.alternative_names = alternative_names
        self.protos = { }

    def add_c_proto(self, decl):
        """
        Add a C function declaration.

        :param str decl:
        :return:
        """

        parsed = parse_file(decl)
        parsed_decl = parsed[0]
        if not parsed_decl:
            raise ValueError('Cannot parse function prototype.')
        func_name, func_decl = parsed_decl.items()[0]

        self.add_proto(func_name, func_decl)

        return func_name, func_decl

    def add_proto(self, func_name, func_decl):
        """
        Add a parsed function prototype.

        :param func_name:
        :param func_decl:
        :return:
        """

        if func_name in self.protos:
            l.warning('Function prototype %s already exists.', func_name)
        self.protos[func_name] = func_decl

    def has_proto(self, func_name):
        """


        :param func_name:
        :return:
        """

        return func_name in self.protos

    def __getitem__(self, func_name):
        if func_name in self.protos:
            return self.protos[func_name]
        raise KeyError('Cannot find prototype of function %s.' % func_name)

    def __contains__(self, func_name):
        return self.has_proto(func_name)
