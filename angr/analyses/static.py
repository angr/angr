# -*- coding: utf-8 -*-
from . import Analysis, register_analysis
import logging
import pefile
import peutils
import elftools
import ntpath   # More reliable if on Windows
import os
import time     # To parse time values in PE header
import requests # For the VirusTotal lookups
import hashlib  # To get hashes of the binary
import sys
import re
from terminaltables import AsciiTable
from textwrap import wrap

l = logging.getLogger('angr.analyses.Static')

# TODO: PE/ELF sections
# TODO: Add debug/warn messages
# TODO: Pull in `pefile` warnings for debug messages (obj._pe.get_warnings())
# TODO: Add terminaltables dependency to module
# TODO: Separate code into utils, defines
# TODO: Don't import the modules that are only used for PE if not analyzing PE

def fmthexbytestr(val):
    return ':'.join('{:02x}'.format(ord(c)) for c in val)

def fmthextxt(val, pad=''):
    return ('{:#0'+str(pad)+'x}').format(val)

def fmtcommanum(val, label=''):
    return ('{:,}'+label).format(val)

def fmtcommabytes(val):
    return lambda: fmtcommanum(val, ' bytes')

def fmttime(val):
    return time.asctime(time.gmtime(val)) + ' UTC'

def make_me_pretty(datadict, header=[['Field', 'Value']]):
    """
    Takes a dictionary in the form of { 'key': ( 'rawval', 'prettyval' ) }
    and returns the string of a formatted ASCII table for printing.

    `prettyval` may be a lambda that returns a string.

    `rawval` is used `if not prettyval` unless `rawval` is a collection,
    in which case it's replaced with a simple descriptor string.

    Sample:
    {'Title':    ( 'Something, Something Dark Side', None ),
     'Authors':  ( ['ThisGuy', 'ThatGal', 'MyDog' ], None ),
     'Glossary': ( [], None ),
     'Year':     ( 1950, int_to_roman(1950) )}

    +----------+--------------------------------+
    | Field    | Value                          |
    +----------+--------------------------------+
    | Authors  | [list] of 3 items/keys         |
    | Glossary | [list] of 0 items/keys         |
    | Title    | Something, something dark side |
    | Year     | MCMLII                         |
    +----------+--------------------------------+
    """
    datalist = []
    for fieldname, tup in datadict.items():

        #l.debug('Checking: %s (type: %s)', tup, type(tup))
        if callable(tup[1]):
            prettyval = tup[1]()
        else:
            prettyval = tup[1]

        if not prettyval:      # Catches None, '', {}, [], etc
            prettyval = tup[0] if not isinstance(tup[0], (list, tuple, dict)) else '[{}] of {:d} items/keys'.format(type(tup[0]).__name__, len(tup[0]))

        datalist.append([fieldname,prettyval])



    datalist = sorted(datalist)
    tbllist = []
    tbllist.extend(header)
    tbllist.extend(datalist)
    table = AsciiTable(tbllist)
    return table.table

class pe_defines:
    '''
    Provides any enum value strings not defined in `pefile`
    '''
    # REF: (IMAGE_OPTIONAL_HEADER structure) https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
    class optional_header:
        magic = { 0x10b: 'IMAGE_NT_OPTIONAL_HDR32_MAGIC',
                  0x20b: 'IMAGE_NT_OPTIONAL_HDR64_MAGIC',
                  0x107: 'IMAGE_ROM_OPTIONAL_HDR_MAGIC' }

    # TODO: Provide OS lookup https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
        #winver = {  }


class Static(Analysis):
    """
    Provides an easier interface to many useful tidbits of information for ELF
    and PE binaries. Every public function returns `None` on failure or a dictionary
    on success and, optionally, pretty-prints the data in formatted ASCII tables to \
    the terminal for easy viewing during interactive analysis.

    Dev Note: If you call a function internally, don't forget to pass `pretty=False`
              so it doesn't spit out a table confusing the user.
    """
    def __init__(self, pretty=False, data_col_wrap=60):
        self.obj            = self.project.loader.main_object
        self.pretty         = pretty
        self.data_col_wrap  = data_col_wrap  #HACK: Each table should get console width and
                                             #      adjust accordingly but 40-60 works for
                                             #      for most cases.

    def get_basics(self, pretty=None):
        """
        Returns some simple attributes of the file itself (size, hashes, name), some
        angr-provided information as well as the results of `get_file_header`.

        Sample dict:
        {'angr_backend': (cle.backends.pe.pe.PE, cle.backends.pe.pe.PE),
         'angr_deps': (['gdi32.dll',
           'psapi.dll',
           'ws2_32.dll',
           'iphlpapi.dll',
        <snip>

        Sample table:
        +------------------+-----------------------------------+
        | Field            | Value                             |
        +------------------+-----------------------------------+
        | angr_backend     | <class 'cle.backends.pe.pe.PE'>   |
        | angr_deps        | gdi32.dll                         |
        |                  |   psapi.dll                       |
        <snip>
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty
        name     = ntpath.basename(obj.binary)
        size     = os.stat(obj.binary).st_size
        secnames = '\n  '.join([s.name.rstrip(' \t\r\n\0') for s in obj.sections])
        hashes   = self.get_hashes(pretty=False)

        basics = {}
        basics['angr_backend']  = ( type(obj),          type(obj) )
        basics['angr_sections'] = ( secnames,           secnames)
        basics['angr_deps']     = ( obj.deps,           '\n  '.join(obj.deps) )
        basics['angr_entry_point'] = ( obj.entry,          lambda: fmthextxt(obj.entry) )
        basics['name']          = ( name,               name )
        basics['size']          = ( size,               lambda: fmtcommabytes(size) )
        basics['md5']           = ( hashes['md5'],      hashes['md5'] )
        basics['sha1']          = ( hashes['sha1'],     ' ↲\n  '.join(wrap(hashes['sha1'], self.data_col_wrap)) )
        basics['sha256']        = ( hashes['sha256'],   ' ↲\n  '.join(wrap(hashes['sha256'], self.data_col_wrap)) )
        basics['sha384']        = ( hashes['sha384'],   ' ↲\n  '.join(wrap(hashes['sha384'], self.data_col_wrap)) )
        basics['sha512']        = ( hashes['sha512'],   ' ↲\n  '.join(wrap(hashes['sha512'], self.data_col_wrap)) )

        fhdr = self.get_file_header(pretty=False)
        for k,v in fhdr.items():
            basics['file_hdr.'+k] = v


        # TODO: Function count, warn if taken from only symbols (no KB or none in KB)
        # TODO: ?Add "include_angr" to add/remove 'angr_' items
        # TODO: Add angr_pic, angr_linked_base, angr_mapped_base

        if pretty:
            print make_me_pretty(basics)

        return basics

    def get_file_header(self, pretty=None):
        """
        For ELF files: gets values parsed by elftools into its `header` attribute.
        For PE files:  gets values from the PE's FILE_HEADER

        Sample dict:
        {'Characteristics':
        (8462,IMAGE_FILE_EXECUTABLE_IMAGE\nIMAGE_FILE_LINE_NUMS_STRIPPED\nIMAGE_FILE_LOCAL_SYMS_STRIPPED\nIMAGE_FILE_32BIT_MACHINE\nIMAGE_FILE_DLL'),
         'Machine':
         (332, 'IMAGE_FILE_MACHINE_I386'),
        <snip>

        Sample table:
        +----------------------+--------------------------------+
        | Field                | Value                          |
        +----------------------+--------------------------------+
        | Characteristics      | IMAGE_FILE_EXECUTABLE_IMAGE    |
        |                      | IMAGE_FILE_LINE_NUMS_STRIPPED  |
        |                      | IMAGE_FILE_LOCAL_SYMS_STRIPPED |
        |                      | IMAGE_FILE_32BIT_MACHINE       |
        |                      | IMAGE_FILE_DLL                 |
        | Machine              | IMAGE_FILE_MACHINE_I386        |
        | NumberOfSections     | 6                              |

        <snip>
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        fhdr = {}
        if hasattr(obj, '_pe'):
            fhdr['Machine']              = ( obj._pe.FILE_HEADER.Machine,               [ i[0] for i in pefile.machine_types if i[1] == obj._pe.FILE_HEADER.Machine ][0] )
            fhdr['NumberOfSections']     = ( obj._pe.FILE_HEADER.NumberOfSections,      None )
            fhdr['TimeDateStamp']        = ( obj._pe.FILE_HEADER.TimeDateStamp,         lambda: fmttime(obj._pe.FILE_HEADER.TimeDateStamp) )
            fhdr['PointerToSymbolTable'] = ( obj._pe.FILE_HEADER.PointerToSymbolTable,  lambda: fmthextxt(obj._pe.FILE_HEADER.PointerToSymbolTable) )
            fhdr['NumberOfSymbols']      = ( obj._pe.FILE_HEADER.NumberOfSymbols,       lambda: fmtcommanum(obj._pe.FILE_HEADER.NumberOfSymbols) )
            fhdr['SizeOfOptionalHeader'] = ( obj._pe.FILE_HEADER.SizeOfOptionalHeader,  lambda: fmtcommabytes(obj._pe.FILE_HEADER.SizeOfOptionalHeader) )
            fhdr['Characteristics']      = ( obj._pe.FILE_HEADER.Characteristics,       '\n'.join([i[0] for i in pefile.image_characteristics if i[1] & obj._pe.FILE_HEADER.Characteristics != 0]) )

        elif hasattr(obj, 'reader'):
            # Temp values needed for lookups below
            v = obj.reader.header['e_version']
            m = obj.reader.header['e_machine']
            t = obj.reader.header['e_type']
            c = obj.reader.header['e_ident']['EI_CLASS']
            d = obj.reader.header['e_ident']['EI_DATA']
            a = obj.reader.header['e_ident']['EI_OSABI']
            g = obj.reader.header['e_ident']['EI_MAG']

            fhdr['e_version']             = ( elftools.elf.enums.ENUM_E_VERSION[v],         v )
            fhdr['e_machine']             = ( elftools.elf.enums.ENUM_E_MACHINE[m],         m )
            fhdr['e_type']                = ( elftools.elf.enums.ENUM_E_TYPE[t],            t )
            fhdr['e_ident.EI_CLASS']      = ( elftools.elf.enums.ENUM_EI_CLASS[c],          c )
            fhdr['e_ident.EI_DATA']       = ( elftools.elf.enums.ENUM_EI_DATA[d],           d )
            fhdr['e_ident.EI_OSABI']      = ( elftools.elf.enums.ENUM_EI_OSABI[a],          a )
            fhdr['e_ident.EI_MAG']        = ( '0x'+''.join('{:02x}'.format(b) for b in g),  '\\x7fELF' )   # HACK: Need to add the extra '\' when taken from chr()
            fhdr['e_flags']               = ( obj.reader.header['e_flags'],                 lambda: fmthextxt(obj.reader.header['e_flags']) )
            fhdr['e_shoff']               = ( obj.reader.header['e_shoff'],                 lambda: fmtcommabytes(obj.reader.header['e_shoff']) )
            fhdr['e_phoff']               = ( obj.reader.header['e_phoff'],                 lambda: fmtcommabytes(obj.reader.header['e_phoff']) )
            fhdr['e_entry']               = ( obj.reader.header['e_entry'],                 lambda: fmthextxt(obj.reader.header['e_entry']) )
            fhdr['e_shentsize']           = ( obj.reader.header['e_shentsize'],             lambda: fmtcommabytes(obj.reader.header['e_shentsize']) )
            fhdr['e_phentsize']           = ( obj.reader.header['e_phentsize'],             lambda: fmtcommabytes(obj.reader.header['e_phentsize']) )
            fhdr['e_ehsize']              = ( obj.reader.header['e_ehsize'],                lambda: fmtcommabytes(obj.reader.header['e_ehsize']) )
            fhdr['e_shstrndx']            = ( obj.reader.header['e_shstrndx'],              None )
            fhdr['e_shnum']               = ( obj.reader.header['e_shnum'],                 None )
            fhdr['e_phnum']               = ( obj.reader.header['e_phnum'],                 None )
            fhdr['e_ident.EI_ABIVERSION'] = ( obj.reader.header['e_ident']['EI_ABIVERSION'],None )
            fhdr['e_ident.EI_VERSION']    = ( obj.reader.header['e_ident']['EI_VERSION'],   None )

        if pretty:
            print make_me_pretty(fhdr)

        return fhdr

    def get_hashes(self, pretty=None):
        """
        Returns the file's hashes for: MD5, SHA1, SHA256, SHA384 and SHA512

        Sample dict:
        {'md5': '1a9fd80174aafecd9a52fd908cb82637',
         'sha1': 'fbe285b8b7fe710724ea35d15948969a709ed33b',
         'sha256': 'eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a',
         'sha384': '2d147ac50a07e7988b5853908f71d7a53f3caccdd78dce62cd29f26b4657a41b85cec7fa6933fb98a04aa205ecc09f91',
         'sha512': '000e50cfc28158a4ed474a6b4f3b5d91aea82b59252f64d98625ccae20d916d8e806babc20750790091ef9db22a98648abb9256c8c10eee08289d1b4d5b00e0b'}

        Sample table:
        +-----------+------------------------------------------------------------------+
        | Hash Type | Hex Digest                                                       |
        +-----------+------------------------------------------------------------------+
        | md5       | 1a9fd80174aafecd9a52fd908cb82637                                 |
        | sha1      | fbe285b8b7fe710724ea35d15948969a709ed33b                         |
        | sha256    | eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aa ↲   |
        |           |   db4a                                                           |
        | sha384    | 2d147ac50a07e7988b5853908f71d7a53f3caccdd78dce62cd29f26b4657 ↲   |
        |           |   a41b85cec7fa6933fb98a04aa205ecc09f91                           |
        | sha512    | 000e50cfc28158a4ed474a6b4f3b5d91aea82b59252f64d98625ccae20d9 ↲   |
        |           |   16d8e806babc20750790091ef9db22a98648abb9256c8c10eee08289d1b4 ↲ |
        |           |   d5b00e0b                                                       |
        +-----------+------------------------------------------------------------------+
        """
        # TODO: Maybe replace ↲ with \ since we're doing "ASCII Tables". Its alignment
        #       seems to be slightly different between monospaced fonts. It aligns
        #       fine in `ProFont for Powerline` in my terminal but, here, it appears
        #       to throw off spacing with `Liberation Mono for Powerline`.

        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        hash_md5    = hashlib.md5()
        hash_sha1   = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        hash_sha384 = hashlib.sha384()
        hash_sha512 = hashlib.sha512()

        with open(obj.binary, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha384.update(chunk)
                hash_sha512.update(chunk)

        out = {'md5':    hash_md5.hexdigest(),
               'sha1':   hash_sha1.hexdigest(),
               'sha256': hash_sha256.hexdigest(),
               'sha384': hash_sha384.hexdigest(),
               'sha512': hash_sha512.hexdigest() }

        if pretty:
            header = [[ 'Hash Type', 'Hex Digest' ]]
            data = sorted([[ k,' ↲\n  '.join(wrap(v, self.data_col_wrap))] for k,v in out.items() ])
            header.extend(data)
            table = AsciiTable(header)
            print table.table

        return out

    def get_imports(self, bylib=True, pretty=None):
        """
        Returns the binaries imports, as understood by angr

        Sample dict (bylib=True):
        {'advapi32.dll': ['RegCreateKeyA',
          'QueryServiceStatus',
          'RegOpenKeyExA',
          'LookupPrivilegeValueA',
          'OpenServiceA',
          'RegQueryValueExA',
          'CloseServiceHandle',
        <snip>

        Sample table (bylib=True):
        +--------------+-----------------------------+
        | Library      | Import                      |
        +--------------+-----------------------------+
        | advapi32.dll | AdjustTokenPrivileges       |
        | advapi32.dll | ChangeServiceConfig2A       |
        | advapi32.dll | ChangeServiceConfigA        |
        | advapi32.dll | CloseServiceHandle          |
        | advapi32.dll | ControlService              |
        <snip>

        Sample dict (bylib=False):
        {'??1type_info@@UAE@XZ': 'msvcrt.dll',
         '??2@YAPAXI@Z': 'msvcrt.dll',
         '??3@YAXPAX@Z': 'msvcrt.dll',
         'AdjustTokenPrivileges': 'advapi32.dll',
         'BitBlt': 'gdi32.dll',
         'BlockInput': 'user32.dll',
         <snip>

        Sample table (bylib=False):
        +-----------------------------+--------------+
        | Import                      | Library      |
        +-----------------------------+--------------+
        | ??1type_info@@UAE@XZ        | msvcrt.dll   |
        | ??2@YAPAXI@Z                | msvcrt.dll   |
        | ??3@YAXPAX@Z                | msvcrt.dll   |
        | AdjustTokenPrivileges       | advapi32.dll |
        | BitBlt                      | gdi32.dll    |
        | BlockInput                  | user32.dll   |
        <snip>
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        imps = {}
        for name, reloc in obj.imports.items():
            imps[name] = reloc.resolvewith

        if pretty:
            hdr = [[ 'Import', 'Library' ]]
            datalist = sorted([ [k,v] for k,v in imps.items() ])

            if bylib:
                hdr = [[ 'Library', 'Import' ]]
                datalist = sorted([ [v,k] for k,v in imps.items() ])


            hdr.extend(datalist)
            table = AsciiTable(hdr)
            print table.table

        if bylib:
            out = {}
            for func,lib in imps.items():
                if lib not in out:
                    out[lib] = list()
                out[lib].append(func)

        else:
            out = imps

        return out

    # TODO: VirusTotal Rescan API (probably check that first in do_virus_total)
    # TODO: Make pretty
    def submit_virus_total(self, apikey, pretty=None):
        """
        API Ref https://www.virustotal.com/en/documentation/public-api/
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        params = {'apikey': apikey}
        files = {'file': (ntpath.basename(obj.binary), obj.binary_stream)}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()

        return json_response

    def get_virus_total_results(self, apikey, resource, pretty=None): #TODO: Make pretty
        pretty   = self.pretty if pretty is None else pretty

        params = {'apikey': apikey, 'resource': resource}
        headers = {
          "Accept-Encoding": "gzip, deflate",
          "User-Agent" : "gzip,  angr binary analysis framework"
          }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
          params=params, headers=headers)
        json_response = response.json()
        return json_response

    def do_virus_total(self, apikey, pretty=None):
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty
        request = submit_virus_total(apikey, obj)
        results = get_virus_total_results(apikey, request['resource'])
        return {'request': request, 'results': results}

    def get_strings(self, charset=None, shortest=4, filter=None, pretty=None):
        """
        Conducts a regex search for strings of at least `shortest` len, containing
        characters in `charset` and, optionally, filtering for only those strings
        containing the string specified in `filter`

        Sample dict:
        {92160: 'ServiceMain',
         103424: 'a2U0',
         88066: 'SelectObject',
         124931: '8r8y8',
         112644: 'xsys.dll',
         126981: '7k7t7z7',
         2057: 'D$Dj',
         19799: 't2PS',
        <snip>

        Sample table:
        +----------+----------------------------------------------------------------+
        | Offset   | Value                                                          |
        +----------+----------------------------------------------------------------+
        | 0x00004e | This program cannot be run in DOS mode.                        |
        | 0x0000ff | bRich                                                          |
        | 0x000208 | .text                                                          |
        | 0x01c2a0 | [Machine IdleTime:] %d days                                    |
        | 0x01c2bd |  %.2d:%.2d:%.2d                                                |
        | 0x01c2d8 | [Machine UpTime:] %-.2d Days %-.2d Hours %-.2d Minutes %-.2d ↲ |
        |          |   Seconds                                                      |
        | 0x01c328 | [Language:] id:0x%x                                            |
        <snip>
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty


        chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> " if charset is None else charset
        shortest_run = shortest

        regexp = '[%s]{%d,}' % (chars, shortest_run)
        data = open(obj.binary, 'rb').read()
        out = {}
        for m in re.compile(regexp).finditer(data):
            out[m.start()] = m.group()

        if filter is not None:
            for k,v in out.items():
                if filter not in v:
                    out.pop(k)

        if pretty:
            header = [['Offset', 'Value']]
            data = sorted([[lambda: fmthextxt(k,8),' ↲\n  '.join(wrap(v, self.data_col_wrap))] for k,v in out.items()])
            header.extend(data)
            table = AsciiTable(header)
            print table.table

        return out

    ################
    # PE Specifics #
    ################

    # TODO: Only define these if the object is a PE and emit a warning

    def peid_signature_scan(self, db_file_path, ep_only=True, sec_start_only=False, get_all=False, pretty=None):
        """
        Exposes `pefile`'s implementation of PEiD signature scanning to identify packers
        and crytpers.

        :param ep_only:         Whether to only scan the entry point against all signatures. If `False`,
                                the scan will take significantly longer.
        :param sec_start_only:  Whether to only scan section starts.
        :param get_all:         Whether to return only the most-likely match or all (where the most
                                likely is the last in the list).

        NOTE: Signature databases can be found around the web: "UserDB.txt peid" will often
        return results.

        Sample dict:
        {'peid_results': ['Armadillo v1.xx - v2.xx']}

        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        # TODO: Support for match_data
        # TODO: Pretty (include offsets for match_all)

        if not hasattr(obj, '_pe'):
            return None

        sigs = peutils.SignatureDatabase(db_file_path)
        matches = None
        if get_all:
            matches = sigs.match_all(pe=obj._pe, ep_only=ep_only, section_start_only=sec_start_only)
        else:
            matches = sigs.match(obj._pe, ep_only)

        return { 'peid_results': matches }

    # TODO: Need a test binary
    #def get_resource_strings(self, pretty=None):
    #    obj      = self.obj
    #    pretty   = self.pretty if pretty is None else pretty
    #
    #    # TODO: dict with resource_name/ID key
    #    # TODO: pretty
    #    if not hasattr(obj, '_pe'):
    #        return None
    #
    #    return obj._pe.get_resources_strings()

    def get_optional_header(self, pretty=None):
        """
        For PE files, returns the values in the OPTIONAL_HEADER table

        Sample dict:
        {'AddressOfEntryPoint': (86381, '0x1516d'),
         'BaseOfCode': (4096, '0x1000'),
         'BaseOfData': (90112, '0x16000'),
         'CheckSum': (0, '0x0'),
         'DllCharacteristics': (0, 'N/A'),
         'FileAlignment': (512, '0x200'),
         'LoaderFlags': (0, '0x0'),
         'Magic': (267, 'IMAGE_NT_OPTIONAL_HDR32_MAGIC'),

        <snip>

        Sample table:
        +-----------------------------+-------------------------------+
        | Field                       | Value                         |
        +-----------------------------+-------------------------------+
        | AddressOfEntryPoint         | 0x1516d                       |
        | BaseOfCode                  | 0x1000                        |
        | BaseOfData                  | 0x16000                       |
        | CheckSum                    | 0x0                           |
        | DllCharacteristics          | N/A                           |
        | FileAlignment               | 0x200                         |
        | LoaderFlags                 | 0x0                           |
        | Magic                       | IMAGE_NT_OPTIONAL_HDR32_MAGIC |
        <snip>
        """
        obj      = self.obj
        pretty   = self.pretty if pretty is None else pretty

        if not hasattr(obj, '_pe'):
            return None

        def fmtdllflags(optheader):
            line = fmthextxt(optheader.DllCharacteristics)
            if not optheader.DllCharacteristics:
                line += ' (N/A)'
            else:
                dll_flags = pefile.retrieve_flags(pefile.DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_')
                for flag in sorted(dll_flags):
                    if getattr(optheader, flag[0]):
                        line += '\n  {} ({})'.format(flag[0], fmthextxt(flag[1]))
            return line

        out = {}
        out['Magic']                    = ( obj._pe.OPTIONAL_HEADER.Magic,                      pe_defines.optional_header.magic[obj._pe.OPTIONAL_HEADER.Magic] )
        out['MajorLinkerVersion']       = ( obj._pe.OPTIONAL_HEADER.MajorLinkerVersion,         None )
        out['MinorLinkerVersion']       = ( obj._pe.OPTIONAL_HEADER.MinorLinkerVersion,         None )
        out['SizeOfCode']               = ( obj._pe.OPTIONAL_HEADER.SizeOfCode,                 lambda: fmtcommabytes(obj._pe.OPTIONAL_HEADER.SizeOfCode) )
        out['SizeOfInitializedData']    = ( obj._pe.OPTIONAL_HEADER.SizeOfInitializedData,      lambda: fmtcommabytes(obj._pe.OPTIONAL_HEADER.SizeOfInitializedData) )
        out['SizeOfUninitializedData']  = ( obj._pe.OPTIONAL_HEADER.SizeOfUninitializedData,    lambda: fmtcommabytes(obj._pe.OPTIONAL_HEADER.SizeOfInitializedData) )
        out['AddressOfEntryPoint']      = ( obj._pe.OPTIONAL_HEADER.AddressOfEntryPoint,        lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.AddressOfEntryPoint) )
        out['BaseOfCode']               = ( obj._pe.OPTIONAL_HEADER.BaseOfCode,                 lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.BaseOfCode) )
        out['BaseOfData']               = ( obj._pe.OPTIONAL_HEADER.BaseOfData,                 lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.BaseOfData) )
        out['SectionAlignment']         = ( obj._pe.OPTIONAL_HEADER.SectionAlignment,           lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.SectionAlignment) )
        out['FileAlignment']            = ( obj._pe.OPTIONAL_HEADER.FileAlignment,              lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.FileAlignment) )
        out['MajorOperatingSystemVersion'] = ( obj._pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, None )
        out['MinorOperatingSystemVersion'] = ( obj._pe.OPTIONAL_HEADER.MinorOperatingSystemVersion, None )
        out['MajorImageVersion']        = ( obj._pe.OPTIONAL_HEADER.MajorImageVersion,          None )
        out['MinorImageVersion']        = ( obj._pe.OPTIONAL_HEADER.MinorImageVersion,          None )
        out['MajorSubsystemVersion']    = ( obj._pe.OPTIONAL_HEADER.MajorSubsystemVersion,      None )
        out['MinorSubsystemVersion']    = ( obj._pe.OPTIONAL_HEADER.MinorSubsystemVersion,      None )
        out['Reserved1']                = ( obj._pe.OPTIONAL_HEADER.Reserved1,                  None )
        out['SizeOfImage']              = ( obj._pe.OPTIONAL_HEADER.SizeOfImage,                lambda: fmtcommabytes(obj._pe.OPTIONAL_HEADER.SizeOfImage) )
        out['SizeOfHeaders']            = ( obj._pe.OPTIONAL_HEADER.SizeOfHeaders,              lambda: fmtcommabytes(obj._pe.OPTIONAL_HEADER.SizeOfHeaders) )
        out['CheckSum']                 = ( obj._pe.OPTIONAL_HEADER.CheckSum,                   lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.CheckSum) )
        out['Subsystem']                = [ i for i in pefile.subsystem_types if i[1] == obj._pe.OPTIONAL_HEADER.Subsystem ][0]

        #dllchar = [ i[0] for i in pefile.dll_characteristics if i[1] == obj._pe.OPTIONAL_HEADER.DllCharacteristics ]
        out['DllCharacteristics'] = ( obj._pe.OPTIONAL_HEADER.DllCharacteristics, lambda: fmtdllflags(obj._pe.OPTIONAL_HEADER) )

        out['SizeOfStackReserve']       = ( obj._pe.OPTIONAL_HEADER.SizeOfStackReserve,         None )
        out['SizeOfStackCommit']        = ( obj._pe.OPTIONAL_HEADER.SizeOfStackCommit,          None )
        out['SizeOfHeapReserve']        = ( obj._pe.OPTIONAL_HEADER.SizeOfHeapReserve,          None )
        out['SizeOfHeapCommit']         = ( obj._pe.OPTIONAL_HEADER.SizeOfHeapCommit,           None )
        out['LoaderFlags']              = ( obj._pe.OPTIONAL_HEADER.LoaderFlags,                lambda: fmthextxt(obj._pe.OPTIONAL_HEADER.LoaderFlags) )
        out['NumberOfRvaAndSizes']      = ( obj._pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,        None )

        if pretty:
            print make_me_pretty(out)
        return out


register_analysis(Static, 'Static')
