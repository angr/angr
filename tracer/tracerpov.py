import xml.etree.ElementTree

class TracerPoV(object):
    '''
    Simple PoV parser for Tracer
    '''

    def __init__(self, filename):
        self.filename = filename

        self._root = xml.etree.ElementTree.parse(self.filename)

        self._raw_writes = self._root.find('replay').findall('write')

        self._clean_writes()

    def _clean_writes(self):
        '''
        decode writes
        '''

        self.writes = [ ]
        for raw_write in self._raw_writes:
            mode = 'ascii'
            if 'format' in raw_write.attrib:
                mode = raw_write.attrib['format']

            d = raw_write.find('data')
            if d is None:
                raise ValueError("could not find data tag inside write element, unsupport element")

            txt = d.text

            if mode == 'ascii':
                body = txt.decode('string-escape')
            elif mode == 'hex':
                body = txt.decode('hex')
            else:
                raise ValueError("unrecognized mode '%s' in file '%s'" % (mode, self.filename))

            self.writes.append(body)
