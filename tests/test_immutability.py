import angr
import nose


def test_immutability():

    class Foo(angr.misc.ImmutabilityMixin):

        def __init__(self, immutable=False):
            super(Foo, self).__init__(immutable=immutable)
            self.bar = 0

        def copy(self):
            foo = Foo(immutable=self._immutable)
            foo.bar = self.bar
            return foo

        @angr.misc.ImmutabilityMixin.immutable
        def foo(self):
            self.bar += 1
            return self

    mutable = Foo(immutable=False)
    mutable.foo()
    nose.tools.assert_equal(mutable.bar, 1)

    immutable = Foo(immutable=True)
    mutated = immutable.foo()
    nose.tools.assert_equal(immutable.bar, 0)
    nose.tools.assert_equal(mutated.bar, 1)


if __name__ == '__main__':
    test_immutability()
