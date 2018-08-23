import angr
import nose


def test_hookset():

    class Foo(object):
        def run(self):
            return self.blah()

        def blah(self): #pylint:disable=no-self-use
            return ['foo']

        def install_hooks(self, tech):
            angr.misc.HookSet.install_hooks(self, blah=tech.blah)

        def remove_hooks(self, tech):
            angr.misc.HookSet.remove_hooks(self, blah=tech.blah)

    class Bar(object):
        def blah(self, foo): #pylint:disable=no-self-use
            return ['bar'] + foo.blah()

    class Baz(object):
        def blah(self, foo): # pylint:disable=no-self-use
            return ['baz'] + foo.blah()

    class Coward(object):
        def blah(self, foo): #pylint:disable=no-self-use,unused-argument
            return ['coward']

    foo = Foo()
    nose.tools.assert_equal(foo.run(), ['foo'])

    bar = Bar()
    baz = Baz()
    foo.install_hooks(bar)
    foo.install_hooks(baz)
    nose.tools.assert_equal(foo.run(), ['baz', 'bar', 'foo'])

    foo.remove_hooks(bar)
    foo.remove_hooks(baz)
    nose.tools.assert_equal(foo.run(), ['foo'])

    coward = Coward()
    foo.install_hooks(coward)
    nose.tools.assert_equal(foo.run(), ['coward'])

    foo.remove_hooks(coward)
    nose.tools.assert_equal(foo.run(), ['foo'])


if __name__ == '__main__':
    test_hookset()
