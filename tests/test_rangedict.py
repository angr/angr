import nose
import rangedict


def test_items():
    rdict = rangedict.RangeDict()
    rdict[0:10] = 'a'
    rdict[5:15] = 'b'
    nose.tools.assert_equal(len(rdict), 2)
    nose.tools.assert_equal(rdict[0:5], ['a'])
    nose.tools.assert_equal(rdict[5:15], ['b'])

    rdict = rangedict.RangeDict()
    rdict[0:15] = 'a'
    rdict[-5:10] = 'b'
    nose.tools.assert_equal(len(rdict), 2)
    nose.tools.assert_equal(rdict[-5:10], ['b'])
    nose.tools.assert_equal(rdict[10:15], ['a'])

    rdict = rangedict.RangeDict()
    rdict[0:10] = 'a'
    rdict[-5:15] = 'b'
    nose.tools.assert_equal(len(rdict), 1)
    nose.tools.assert_equal(rdict[-5:15], ['b'])

    rdict = rangedict.RangeDict()
    rdict[-5:15] = 'a'
    rdict[0:10] = 'b'
    nose.tools.assert_equal(len(rdict), 3)
    nose.tools.assert_equal(rdict[-5:0], ['a'])
    nose.tools.assert_equal(rdict[0:10], ['b'])
    nose.tools.assert_equal(rdict[10:15], ['a'])

    rdict = rangedict.RangeDict()
    rdict[0:5] = 'a'
    rdict[10:15] = 'a'
    rdict[5:10] = 'a'
    nose.tools.assert_equal(len(rdict), 1)
    nose.tools.assert_equal(rdict[0:15], ['a'])

    rdict = rangedict.RangeDict()
    rdict[0:5] = 'b'
    rdict[10:15] = 'a'
    rdict[5:10] = 'a'
    nose.tools.assert_equal(len(rdict), 2)
    nose.tools.assert_equal(rdict[0:5], ['b'])
    nose.tools.assert_equal(rdict[5:15], ['a'])

    rdict = rangedict.RangeDict()
    rdict[0:5] = 'b'
    rdict[5:10] = 'a'
    rdict[3:8] = 'c'
    nose.tools.assert_equal(len(rdict), 3)
    nose.tools.assert_equal(rdict[0:3], ['b'])
    nose.tools.assert_equal(rdict[3:8], ['c'])
    nose.tools.assert_equal(rdict[8:10], ['a'])


if __name__ == "__main__":
    test_items()
