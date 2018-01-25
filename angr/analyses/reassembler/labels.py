from itertools import count

class Label(object):
    g_label_ctr = count()

    def __init__(self, binary, name, original_addr=None):

        self.binary = binary
        self.name = name

        self.assigned = False

        self.var_size = None

        if self.name is None:
            self.name = "label_%d" % Label.g_label_ctr.next()

        self.original_addr = original_addr
        self.base_addr = None
        self.label_prefix = "@"
        if self.binary.project.arch.name in ['ARMEL']: #arm functions are %funcname
            self.label_prefix = "%"


    #
    # Overridden predefined methods
    #

    def __str__(self):
        """

        :return:
        """

        #if self.var_size is not None:
        #    s = ".type {name},@object\n.comm {name},{size},{size}".format(name=self.name, size=self.var_size)
        #else:
        s = ".{name}:".format(name=self.name)
        return s

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, Label):
            return self.name == other.name
        elif isinstance(other, str):
            return self.name == other
        else:
            raise ValueError("Labels can only be compared against other labels or strings")


    #
    # Properties
    #

    @property
    def operand_str(self):
        if self.base_addr is None:
            return ".%s" % self.name
        else:
            offset = self.offset
            sign = '+' if offset >= 0 else '-'
            offset = abs(offset)
            return ".%s%s%d" % (self.name, sign, offset)

    @property
    def offset(self):
        if self.base_addr is None:
            return 0
        return self.original_addr - self.base_addr

    #
    # Static methods
    #

    @staticmethod
    def new_label(binary, name=None, function_name=None, original_addr=None, data_label=False):
        if function_name is not None:
            return FunctionLabel(binary, function_name, original_addr)
        elif data_label:
            return DataLabel(binary, original_addr)
        else:
            return Label(binary, name, original_addr=original_addr)


class DataLabel(Label):
    def __init__(self, binary, original_addr, name=None):
        Label.__init__(self, binary, name, original_addr=original_addr)

    @property
    def operand_str(self):
        if self.base_addr is None:
            return self.name
        else:
            offset = self.offset
            sign = '+' if offset >= 0 else '-'
            offset = abs(offset)
            return '(%s%s%s)' % (self.name, sign, offset)

    def __str__(self):
        #if self.var_size is not None:
        #    s = ".comm {name},{size},{size}".format(name=self.name, size=self.var_size)
        #else:
        s = "%s:" % (self.name)
        return s


class FunctionLabel(Label):
    def __init__(self, binary, function_name, original_addr, plt=False):
        Label.__init__(self, binary, function_name, original_addr=original_addr)

        self.plt = plt

    @property
    def function_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {func_name}\n" +
                "\t.type {func_name}, {label_prefix}function\n" +
                "{func_name}:").format(
            label_prefix=self.label_prefix,
            func_name=self.function_name
        )


class ObjectLabel(Label):
    def __init__(self, binary, symbol_name, original_addr, plt=False):
        Label.__init__(self, binary, symbol_name, original_addr=original_addr)

        self.plt = plt

    @property
    def symbol_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {symbol_name}\n" +
                "\t.type {symbol_name}, {label_prefix}object\n" +
                "{symbol_name}:").format(
            label_prefix = self.label_prefix,
            symbol_name=self.symbol_name
        )


class NotypeLabel(Label):
    def __init__(self, binary, symbol_name, original_addr, plt=False):
        Label.__init__(self, binary, symbol_name, original_addr=original_addr)

        self.plt = plt

    @property
    def symbol_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {symbol_name}\n" +
                "\t.type {symbol_name}, {label_prefix}notype\n" +
                "{symbol_name}:").format(
            label_prefix = self.label_prefix,
            symbol_name=self.symbol_name
        )


