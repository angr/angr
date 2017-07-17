
import logging

from ..sim_type import parse_file

l = logging.getLogger('angr.declarations.sim_declarations')


class SimDeclarations(object):
    """
    A storage of function declarations.
    """

    def __init__(self, library_name, alternative_names=None):
        self.library_name = library_name
        self.alternative_names = alternative_names
        self.decls = { }

    def add_c_decl(self, decl):
        """
        Add a C function declaration.

        :param str decl:
        :return:
        """

        parsed = parse_file(decl)
        parsed_decl = parsed[0]
        if not parsed_decl:
            raise ValueError('Cannot parse function declaration.')
        func_name, func_decl = parsed_decl.items()[0]

        self.add_decl(func_name, func_decl)

    def add_decl(self, func_name, func_decl):
        """
        Add a parsed function declaration.

        :param func_name:
        :param func_decl:
        :return:
        """

        if func_name in self.decls:
            l.warning('Function declaration %s already exists.', func_name)
        self.decls[func_name] = func_decl

    def has_decl(self, func_name):
        """


        :param func_name:
        :return:
        """

        return func_name in self.decls

    def __getitem__(self, func_name):
        if func_name in self.decls:
            return self.decls[func_name]
        raise KeyError('Cannot find prototype of function %s.' % func_name)

    def __contains__(self, func_name):
        return self.has_decl(func_name)
