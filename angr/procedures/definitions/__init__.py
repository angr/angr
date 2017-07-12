import copy

SIM_LIBRARIES = {}

class SimLibrary(object):
    def __init__(self):
        self.procedures = {}
        self.default_ccs = []

    def add(self, name, procedure, **kwargs):
        kwargs['display_name'] = name
        self.procedures[name] = procedure(**kwargs)

    def add_all_from_dict(self, dictionary, **kwargs):
        for name, procedure in dictionary.iteritems():
            self.add(name, procedure, **kwargs)

    def add_alias(self, name, *alt_names):
        old_procedure = self.procedures[name]
        for alt in alt_names:
            new_procedure = copy.deepcopy(old_procedure)
            new_procedure.display_name = alt
            self.procedures[alt] = new_procedure

    def get(self, name):
