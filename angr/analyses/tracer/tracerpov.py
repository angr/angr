import xml.etree.ElementTree

class TracerPoV(object):
    '''
    Simple PoV parser for Tracer
    '''

    def __init__(self, filename):
        self.filename = filename

        self._root = xml.etree.ElementTree.parse(self.filename)

        self._raw_writes = self._root.find('replay').findall('write')

        self._raw_reads = self._root.find('replay').findall('read')
        self._collect_variables()
        self._clean_writes()


    def _collect_variables(self):
        self._variables = dict()
        for raw_read in self._raw_reads:
            for ele in raw_read.getchildren():
                if ele.tag == 'delim':
                    current_var = ele.text
                elif ele.tag == 'data':
                    current_var = ele.text
                elif ele.tag == 'assign':
                    varname = ele.find('var').text
                    if not ele.find('slice') is None:
                        begin = ele.find('slice').attrib.get('begin')
                        end = ele.find('slice').attrib.get('end')
                        if not begin is None: begin = ord(begin) - ord('0')
                        if not end is None: end = ord(end) - ord('0')
                    else:
                        begin = None
                        end = None
                    self._variables[varname] = current_var[begin:end]

    def _clean_writes(self):
        '''
        decode writes
        '''

        self.writes = []
        for raw_write in self._raw_writes:
            mode = 'ascii'
            if 'format' in raw_write.attrib:
                mode = raw_write.attrib['format']
            d = filter(lambda ele:
                    ele.tag == 'data' or ele.tag == 'var',
                    raw_write.getchildren())
            if d is None:
                raise ValueError("could not find data tag inside write element, unsupport element")

            body = ''
            for i in d:
                mode_i = i.attrib.get('format', mode)
                if i.tag == 'data':
                    text = i.text
                else:
                    text = self._variables[i.text]
                if mode_i == 'ascii':
                    body += text.decode('string-escape')
                elif mode_i == 'hex':
                    body += text.strip().replace('\n', '').decode('hex')
                else:
                    raise ValueError("unrecognized mode '%s' in file '%s'" % (mode_i, self.filename))
            self.writes.append(body)


def test():
    tracerpov = TracerPoV('../tests/for-release__GEN_00391.xml')
    print tracerpov.writes

if __name__ == "__main__":
    test()
