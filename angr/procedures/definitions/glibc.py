
import logging

from ...sim_type import SimTypeFunction, \
    SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, \
    SimTypePointer, \
    SimTypeChar, \
    SimStruct, \
    SimTypeFixedSizeArray, \
    SimTypeBottom
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger('angr.prototypes.libc')


libc = SimLibrary()
libc.set_library_names('libc.so.0', 'libc.so.1', 'libc.so.2', 'libc.so.3', 'libc.so.4', 'libc.so.5', 'libc.so.6', 'libc.so.7', 'libc.so')
libc.add_all_from_dict(P['libc'])
libc.add_all_from_dict(P['posix'])
libc.add_all_from_dict(P['glibc'])
libc.add_alias('abort', '__assert_fail', '__stack_chk_fail')
libc.add_alias('memcpy', 'memmove', 'bcopy')
libc.add_alias('getc', '_IO_getc')
libc.add_alias('putc', '_IO_putc')
libc.set_non_returning('exit_group', 'exit', 'abort', 'pthread_exit', '__assert_fail',
    'longjmp', 'siglongjmp', '__longjmp_chk', '__siglongjmp_chk')


#
# parsed function prototypes
#

_libc_decls = \
    {
        # char * strerror (int ERRNUM);
        "strerror": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * strerror_r (int ERRNUM, char *BUF, size_t N);
        "strerror_r": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void perror (const char *MESSAGE);
        "perror": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void error (int STATUS, int ERRNUM, const char *FORMAT, ...);
        "error": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void error_at_line (int STATUS, int ERRNUM, const char *FNAME, unsigned int LINENO, const char *FORMAT, ...);
        "error_at_line": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void warn (const char *FORMAT, ...);
        "warn": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void vwarn (const char *FORMAT, va_list AP);
        "vwarn": None,
        # void warnx (const char *FORMAT, ...);
        "warnx": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void vwarnx (const char *FORMAT, va_list AP);
        "vwarnx": None,
        # void err (int STATUS, const char *FORMAT, ...);
        "err": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void verr (int STATUS, const char *FORMAT, va_list AP);
        "verr": None,
        # void errx (int STATUS, const char *FORMAT, ...);
        "errx": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void verrx (int STATUS, const char *FORMAT, va_list AP);
        "verrx": None,
        # void * malloc (size_t SIZE);
        "malloc": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void free (void *PTR);
        "free": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeBottom(), label=None),
        # void * realloc (void *PTR, size_t NEWSIZE);
        "realloc": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * reallocarray (void *PTR, size_t NMEMB, size_t SIZE);
        "reallocarray": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * calloc (size_t COUNT, size_t ELTSIZE);
        "calloc": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * aligned_alloc (size_t ALIGNMENT, size_t SIZE);
        "aligned_alloc": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * memalign (size_t BOUNDARY, size_t SIZE);
        "memalign": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int posix_memalign (void **MEMPTR, size_t ALIGNMENT, size_t SIZE);
        "posix_memalign": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void * valloc (size_t SIZE);
        "valloc": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int mallopt (int PARAM, int VALUE);
        "mallopt": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int mcheck (void (*ABORTFN) (enum mcheck_status STATUS));
        "mcheck": None,
        # enum mcheck_status mprobe (void *POINTER);
        "mprobe": None,
        # struct mallinfo mallinfo (void);
        "mallinfo": SimTypeFunction([ ], SimStruct({}, name="mallinfo", pack=True), label=None),
        # void mtrace (void);
        "mtrace": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void muntrace (void);
        "muntrace": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int obstack_init (struct obstack *OBSTACK_PTR);
        "obstack_init": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void * obstack_alloc (struct obstack *OBSTACK_PTR, int SIZE);
        "obstack_alloc": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * obstack_copy (struct obstack *OBSTACK_PTR, void *ADDRESS, int SIZE);
        "obstack_copy": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * obstack_copy0 (struct obstack *OBSTACK_PTR, void *ADDRESS, int SIZE);
        "obstack_copy0": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void obstack_free (struct obstack *OBSTACK_PTR, void *OBJECT);
        "obstack_free": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeBottom(), label=None),
        # void obstack_blank (struct obstack *OBSTACK_PTR, int SIZE);
        "obstack_blank": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void obstack_grow (struct obstack *OBSTACK_PTR, void *DATA, int SIZE);
        "obstack_grow": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void obstack_grow0 (struct obstack *OBSTACK_PTR, void *DATA, int SIZE);
        "obstack_grow0": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void obstack_1grow (struct obstack *OBSTACK_PTR, char C);
        "obstack_1grow": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeChar(label=None)], SimTypeBottom(), label=None),
        # void obstack_ptr_grow (struct obstack *OBSTACK_PTR, void *DATA);
        "obstack_ptr_grow": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeBottom(), label=None),
        # void obstack_int_grow (struct obstack *OBSTACK_PTR, int DATA);
        "obstack_int_grow": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void * obstack_finish (struct obstack *OBSTACK_PTR);
        "obstack_finish": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int obstack_object_size (struct obstack *OBSTACK_PTR);
        "obstack_object_size": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int obstack_room (struct obstack *OBSTACK_PTR);
        "obstack_room": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void obstack_1grow_fast (struct obstack *OBSTACK_PTR, char C);
        "obstack_1grow_fast": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeChar(label=None)], SimTypeBottom(), label=None),
        # void obstack_ptr_grow_fast (struct obstack *OBSTACK_PTR, void *DATA);
        "obstack_ptr_grow_fast": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeBottom(), label=None),
        # void obstack_int_grow_fast (struct obstack *OBSTACK_PTR, int DATA);
        "obstack_int_grow_fast": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void obstack_blank_fast (struct obstack *OBSTACK_PTR, int SIZE);
        "obstack_blank_fast": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void * obstack_base (struct obstack *OBSTACK_PTR);
        "obstack_base": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * alloca (size_t SIZE);
        "alloca": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int brk (void *ADDR);
        "brk": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void *sbrk (ptrdiff_t DELTA);
        "sbrk": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int mlock (const void *ADDR, size_t LEN);
        "mlock": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int munlock (const void *ADDR, size_t LEN);
        "munlock": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int mlockall (int FLAGS);
        "mlockall": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int munlockall (void);
        "munlockall": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int islower (int C);
        "islower": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isupper (int C);
        "isupper": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isalpha (int C);
        "isalpha": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isdigit (int C);
        "isdigit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isalnum (int C);
        "isalnum": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isxdigit (int C);
        "isxdigit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int ispunct (int C);
        "ispunct": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isspace (int C);
        "isspace": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isblank (int C);
        "isblank": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isgraph (int C);
        "isgraph": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isprint (int C);
        "isprint": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int iscntrl (int C);
        "iscntrl": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int isascii (int C);
        "isascii": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int tolower (int C);
        "tolower": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int toupper (int C);
        "toupper": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int toascii (int C);
        "toascii": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int _tolower (int C);
        "_tolower": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int _toupper (int C);
        "_toupper": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # wctype_t wctype (const char *PROPERTY);
        "wctype": None,
        # int iswctype (wint_t WC, wctype_t DESC);
        "iswctype": None,
        # int iswalnum (wint_t WC);
        "iswalnum": None,
        # int iswalpha (wint_t WC);
        "iswalpha": None,
        # int iswcntrl (wint_t WC);
        "iswcntrl": None,
        # int iswdigit (wint_t WC);
        "iswdigit": None,
        # int iswgraph (wint_t WC);
        "iswgraph": None,
        # int iswlower (wint_t WC);
        "iswlower": None,
        # int iswprint (wint_t WC);
        "iswprint": None,
        # int iswpunct (wint_t WC);
        "iswpunct": None,
        # int iswspace (wint_t WC);
        "iswspace": None,
        # int iswupper (wint_t WC);
        "iswupper": None,
        # int iswxdigit (wint_t WC);
        "iswxdigit": None,
        # int iswblank (wint_t WC);
        "iswblank": None,
        # wctrans_t wctrans (const char *PROPERTY);
        "wctrans": None,
        # wint_t towctrans (wint_t WC, wctrans_t DESC);
        "towctrans": None,
        # wint_t towlower (wint_t WC);
        "towlower": None,
        # wint_t towupper (wint_t WC);
        "towupper": None,
        # size_t strlen (const char *S);
        "strlen": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcslen (const wchar_t *WS);
        "wcslen": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t strnlen (const char *S, size_t MAXLEN);
        "strnlen": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcsnlen (const wchar_t *WS, size_t MAXLEN);
        "wcsnlen": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # void * memcpy (void *restrict TO, const void *restrict FROM, size_t SIZE);
        "memcpy": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # wchar_t * wmemcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);
        "wmemcpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # void * mempcpy (void *restrict TO, const void *restrict FROM, size_t SIZE);
        "mempcpy": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # wchar_t * wmempcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);
        "wmempcpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # void * memmove (void *TO, const void *FROM, size_t SIZE);
        "memmove": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # wchar_t * wmemmove (wchar_t *WTO, const wchar_t *WFROM, size_t SIZE);
        "wmemmove": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # void * memccpy (void *restrict TO, const void *restrict FROM, int C, size_t SIZE);
        "memccpy": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * memset (void *BLOCK, int C, size_t SIZE);
        "memset": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # wchar_t * wmemset (wchar_t *BLOCK, wchar_t WC, size_t SIZE);
        "wmemset": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeShort(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strcpy (char *restrict TO, const char *restrict FROM);
        "strcpy": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcscpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM);
        "wcscpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strdup (const char *S);
        "strdup": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcsdup (const wchar_t *WS);
        "wcsdup": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * stpcpy (char *restrict TO, const char *restrict FROM);
        "stpcpy": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcpcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM);
        "wcpcpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # void bcopy (const void *FROM, void *TO, size_t SIZE);
        "bcopy": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeBottom(), label=None),
        # void bzero (void *BLOCK, size_t SIZE);
        "bzero": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeBottom(), label=None),
        # char * strcat (char *restrict TO, const char *restrict FROM);
        "strcat": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcscat (wchar_t *restrict WTO, const wchar_t *restrict WFROM);
        "wcscat": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strncpy (char *restrict TO, const char *restrict FROM, size_t SIZE);
        "strncpy": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcsncpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);
        "wcsncpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strndup (const char *S, size_t SIZE);
        "strndup": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * stpncpy (char *restrict TO, const char *restrict FROM, size_t SIZE);
        "stpncpy": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcpncpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);
        "wcpncpy": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strncat (char *restrict TO, const char *restrict FROM, size_t SIZE);
        "strncat": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcsncat (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);
        "wcsncat": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # int memcmp (const void *A1, const void *A2, size_t SIZE);
        "memcmp": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int wmemcmp (const wchar_t *A1, const wchar_t *A2, size_t SIZE);
        "wmemcmp": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int strcmp (const char *S1, const char *S2);
        "strcmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int wcscmp (const wchar_t *WS1, const wchar_t *WS2);
        "wcscmp": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int strcasecmp (const char *S1, const char *S2);
        "strcasecmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int wcscasecmp (const wchar_t *WS1, const wchar_t *WS2);
        "wcscasecmp": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int strncmp (const char *S1, const char *S2, size_t SIZE);
        "strncmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int wcsncmp (const wchar_t *WS1, const wchar_t *WS2, size_t SIZE);
        "wcsncmp": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int strncasecmp (const char *S1, const char *S2, size_t N);
        "strncasecmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int wcsncasecmp (const wchar_t *WS1, const wchar_t *S2, size_t N);
        "wcsncasecmp": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int strverscmp (const char *S1, const char *S2);
        "strverscmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int bcmp (const void *A1, const void *A2, size_t SIZE);
        "bcmp": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int strcoll (const char *S1, const char *S2);
        "strcoll": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int wcscoll (const wchar_t *WS1, const wchar_t *WS2);
        "wcscoll": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # size_t strxfrm (char *restrict TO, const char *restrict FROM, size_t SIZE);
        "strxfrm": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcsxfrm (wchar_t *restrict WTO, const wchar_t *WFROM, size_t SIZE);
        "wcsxfrm": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # void * memchr (const void *BLOCK, int C, size_t SIZE);
        "memchr": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # wchar_t * wmemchr (const wchar_t *BLOCK, wchar_t WC, size_t SIZE);
        "wmemchr": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeShort(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # void * rawmemchr (const void *BLOCK, int C);
        "rawmemchr": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * memrchr (const void *BLOCK, int C, size_t SIZE);
        "memrchr": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # char * strchr (const char *STRING, int C);
        "strchr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcschr (const wchar_t *WSTRING, int WC);
        "wcschr": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strchrnul (const char *STRING, int C);
        "strchrnul": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcschrnul (const wchar_t *WSTRING, wchar_t WC);
        "wcschrnul": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeShort(signed=True, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strrchr (const char *STRING, int C);
        "strrchr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcsrchr (const wchar_t *WSTRING, wchar_t C);
        "wcsrchr": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeShort(signed=True, label=None)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strstr (const char *HAYSTACK, const char *NEEDLE);
        "strstr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcsstr (const wchar_t *HAYSTACK, const wchar_t *NEEDLE);
        "wcsstr": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # wchar_t * wcswcs (const wchar_t *HAYSTACK, const wchar_t *NEEDLE);
        "wcswcs": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strcasestr (const char *HAYSTACK, const char *NEEDLE);
        "strcasestr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void * memmem (const void *HAYSTACK, size_t HAYSTACK_LEN, const void *NEEDLE, size_t NEEDLE_LEN);
        "memmem": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # size_t strspn (const char *STRING, const char *SKIPSET);
        "strspn": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcsspn (const wchar_t *WSTRING, const wchar_t *SKIPSET);
        "wcsspn": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t strcspn (const char *STRING, const char *STOPSET);
        "strcspn": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcscspn (const wchar_t *WSTRING, const wchar_t *STOPSET);
        "wcscspn": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # char * strpbrk (const char *STRING, const char *STOPSET);
        "strpbrk": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcspbrk (const wchar_t *WSTRING, const wchar_t *STOPSET);
        "wcspbrk": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * index (const char *STRING, int C);
        "index": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * rindex (const char *STRING, int C);
        "rindex": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * strtok (char *restrict NEWSTRING, const char *restrict DELIMITERS);
        "strtok": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # wchar_t * wcstok (wchar_t *NEWSTRING, const wchar_t *DELIMITERS, wchar_t **SAVE_PTR);
        "wcstok": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0)], SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None),
        # char * strtok_r (char *NEWSTRING, const char *DELIMITERS, char **SAVE_PTR);
        "strtok_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * strsep (char **STRING_PTR, const char *DELIMITER);
        "strsep": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * basename (const char *FILENAME);
        "basename": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * dirname (char *PATH);
        "dirname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void explicit_bzero (void *BLOCK, size_t LEN);
        "explicit_bzero": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeBottom(), label=None),
        # char * strfry (char *STRING);
        "strfry": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void * memfrob (void *MEM, size_t LENGTH);
        "memfrob": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # char * l64a (long int N);
        "l64a": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # long int a64l (const char *STRING);
        "a64l": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # error_t argz_create (char *const ARGV[], char **ARGZ, size_t *ARGZ_LEN);
        "argz_create": None,
        # error_t argz_create_sep (const char *STRING, int SEP, char **ARGZ, size_t *ARGZ_LEN);
        "argz_create_sep": None,
        # size_t argz_count (const char *ARGZ, size_t ARGZ_LEN);
        "argz_count": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # void argz_extract (const char *ARGZ, size_t ARGZ_LEN, char **ARGV);
        "argz_extract": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeBottom(), label=None),
        # void argz_stringify (char *ARGZ, size_t LEN, int SEP);
        "argz_stringify": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # error_t argz_add (char **ARGZ, size_t *ARGZ_LEN, const char *STR);
        "argz_add": None,
        # error_t argz_add_sep (char **ARGZ, size_t *ARGZ_LEN, const char *STR, int DELIM);
        "argz_add_sep": None,
        # error_t argz_append (char **ARGZ, size_t *ARGZ_LEN, const char *BUF, size_t BUF_LEN);
        "argz_append": None,
        # void argz_delete (char **ARGZ, size_t *ARGZ_LEN, char *ENTRY);
        "argz_delete": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # error_t argz_insert (char **ARGZ, size_t *ARGZ_LEN, char *BEFORE, const char *ENTRY);
        "argz_insert": None,
        # char * argz_next (const char *ARGZ, size_t ARGZ_LEN, const char *ENTRY);
        "argz_next": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # error_t argz_replace (char **ARGZ, size_t *ARGZ_LEN, const char *STR, const char *WITH, unsigned *REPLACE_COUNT);
        "argz_replace": None,
        # char * envz_entry (const char *ENVZ, size_t ENVZ_LEN, const char *NAME);
        "envz_entry": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * envz_get (const char *ENVZ, size_t ENVZ_LEN, const char *NAME);
        "envz_get": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # error_t envz_add (char **ENVZ, size_t *ENVZ_LEN, const char *NAME, const char *VALUE);
        "envz_add": None,
        # error_t envz_merge (char **ENVZ, size_t *ENVZ_LEN, const char *ENVZ2, size_t ENVZ2_LEN, int OVERRIDE);
        "envz_merge": None,
        # void envz_strip (char **ENVZ, size_t *ENVZ_LEN);
        "envz_strip": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void envz_remove (char **ENVZ, size_t *ENVZ_LEN, const char *NAME);
        "envz_remove": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # int mbsinit (const mbstate_t *PS);
        "mbsinit": None,
        # wint_t btowc (int C);
        "btowc": None,
        # int wctob (wint_t C);
        "wctob": None,
        # size_t mbrtowc (wchar_t *restrict PWC, const char *restrict S, size_t N, mbstate_t *restrict PS);
        "mbrtowc": None,
        # size_t mbrlen (const char *restrict S, size_t N, mbstate_t *PS);
        "mbrlen": None,
        # size_t wcrtomb (char *restrict S, wchar_t WC, mbstate_t *restrict PS);
        "wcrtomb": None,
        # size_t mbsrtowcs (wchar_t *restrict DST, const char **restrict SRC, size_t LEN, mbstate_t *restrict PS);
        "mbsrtowcs": None,
        # size_t wcsrtombs (char *restrict DST, const wchar_t **restrict SRC, size_t LEN, mbstate_t *restrict PS);
        "wcsrtombs": None,
        # size_t mbsnrtowcs (wchar_t *restrict DST, const char **restrict SRC, size_t NMC, size_t LEN, mbstate_t *restrict PS);
        "mbsnrtowcs": None,
        # size_t wcsnrtombs (char *restrict DST, const wchar_t **restrict SRC, size_t NWC, size_t LEN, mbstate_t *restrict PS);
        "wcsnrtombs": None,
        # int mbtowc (wchar_t *restrict RESULT, const char *restrict STRING, size_t SIZE);
        "mbtowc": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int wctomb (char *STRING, wchar_t WCHAR);
        "wctomb": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeShort(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int mblen (const char *STRING, size_t SIZE);
        "mblen": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # size_t mbstowcs (wchar_t *WSTRING, const char *STRING, size_t SIZE);
        "mbstowcs": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcstombs (char *STRING, const wchar_t *WSTRING, size_t SIZE);
        "wcstombs": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # iconv_t iconv_open (const char *TOCODE, const char *FROMCODE);
        "iconv_open": None,
        # int iconv_close (iconv_t CD);
        "iconv_close": None,
        # size_t iconv (iconv_t CD, char **INBUF, size_t *INBYTESLEFT, char **OUTBUF, size_t *OUTBYTESLEFT);
        "iconv": None,
        # char * setlocale (int CATEGORY, const char *LOCALE);
        "setlocale": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # struct lconv * localeconv (void);
        "localeconv": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="lconv", pack=True), label=None, offset=0), label=None),
        # char * nl_langinfo (nl_item ITEM);
        "nl_langinfo": None,
        # ssize_t strfmon (char *S, size_t MAXSIZE, const char *FORMAT, ...);
        "strfmon": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # int rpmatch (const char *RESPONSE);
        "rpmatch": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # nl_catd catopen (const char *CAT_NAME, int FLAG);
        "catopen": None,
        # char * catgets (nl_catd CATALOG_DESC, int SET, int MESSAGE, const char *STRING);
        "catgets": None,
        # int catclose (nl_catd CATALOG_DESC);
        "catclose": None,
        # char * gettext (const char *MSGID);
        "gettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * dgettext (const char *DOMAINNAME, const char *MSGID);
        "dgettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * dcgettext (const char *DOMAINNAME, const char *MSGID, int CATEGORY);
        "dcgettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * textdomain (const char *DOMAINNAME);
        "textdomain": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * bindtextdomain (const char *DOMAINNAME, const char *DIRNAME);
        "bindtextdomain": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * ngettext (const char *MSGID1, const char *MSGID2, unsigned long int N);
        "ngettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * dngettext (const char *DOMAIN, const char *MSGID1, const char *MSGID2, unsigned long int N);
        "dngettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * dcngettext (const char *DOMAIN, const char *MSGID1, const char *MSGID2, unsigned long int N, int CATEGORY);
        "dcngettext": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * bind_textdomain_codeset (const char *DOMAINNAME, const char *CODESET);
        "bind_textdomain_codeset": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void * lfind (const void *KEY, const void *BASE, size_t *NMEMB, size_t SIZE, comparison_fn_t COMPAR);
        "lfind": None,
        # void * lsearch (const void *KEY, void *BASE, size_t *NMEMB, size_t SIZE, comparison_fn_t COMPAR);
        "lsearch": None,
        # void * bsearch (const void *KEY, const void *ARRAY, size_t COUNT, size_t SIZE, comparison_fn_t COMPARE);
        "bsearch": None,
        # void qsort (void *ARRAY, size_t COUNT, size_t SIZE, comparison_fn_t COMPARE);
        "qsort": None,
        # int hcreate (size_t NEL);
        "hcreate": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void hdestroy (void);
        "hdestroy": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # ENTRY * hsearch (ENTRY ITEM, ACTION ACTION);
        "hsearch": None,
        # int hcreate_r (size_t NEL, struct hsearch_data *HTAB);
        "hcreate_r": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypePointer(SimStruct({}, name="hsearch_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void hdestroy_r (struct hsearch_data *HTAB);
        "hdestroy_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="hsearch_data", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int hsearch_r (ENTRY ITEM, ACTION ACTION, ENTRY **RETVAL, struct hsearch_data *HTAB);
        "hsearch_r": None,
        # void * tsearch (const void *KEY, void **ROOTP, comparison_fn_t COMPAR);
        "tsearch": None,
        # void * tfind (const void *KEY, void *const *ROOTP, comparison_fn_t COMPAR);
        "tfind": None,
        # void * tdelete (const void *KEY, void **ROOTP, comparison_fn_t COMPAR);
        "tdelete": None,
        # void tdestroy (void *VROOT, __free_fn_t FREEFCT);
        "tdestroy": None,
        # void twalk (const void *ROOT, __action_fn_t ACTION);
        "twalk": None,
        # int fnmatch (const char *PATTERN, const char *STRING, int FLAGS);
        "fnmatch": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int glob (const char *PATTERN, int FLAGS, int (*ERRFUNC) (const char *FILENAME, int ERROR_CODE), glob_t *VECTOR_PTR);
        "glob": None,
        # int glob64 (const char *PATTERN, int FLAGS, int (*ERRFUNC) (const char *FILENAME, int ERROR_CODE), glob64_t *VECTOR_PTR);
        "glob64": None,
        # void globfree (glob_t *PGLOB);
        "globfree": None,
        # void globfree64 (glob64_t *PGLOB);
        "globfree64": None,
        # int regcomp (regex_t *restrict COMPILED, const char *restrict PATTERN, int CFLAGS);
        "regcomp": None,
        # int regexec (const regex_t *restrict COMPILED, const char *restrict STRING, size_t NMATCH, regmatch_t MATCHPTR[restrict], int EFLAGS);
        "regexec": None,
        # void regfree (regex_t *COMPILED);
        "regfree": None,
        # size_t regerror (int ERRCODE, const regex_t *restrict COMPILED, char *restrict BUFFER, size_t LENGTH);
        "regerror": None,
        # int wordexp (const char *WORDS, wordexp_t *WORD_VECTOR_PTR, int FLAGS);
        "wordexp": None,
        # void wordfree (wordexp_t *WORD_VECTOR_PTR);
        "wordfree": None,
        # FILE * fopen (const char *FILENAME, const char *OPENTYPE);
        "fopen": None,
        # FILE * fopen64 (const char *FILENAME, const char *OPENTYPE);
        "fopen64": None,
        # FILE * freopen (const char *FILENAME, const char *OPENTYPE, FILE *STREAM);
        "freopen": None,
        # FILE * freopen64 (const char *FILENAME, const char *OPENTYPE, FILE *STREAM);
        "freopen64": None,
        # int __freadable (FILE *STREAM);
        "__freadable": None,
        # int __fwritable (FILE *STREAM);
        "__fwritable": None,
        # int __freading (FILE *STREAM);
        "__freading": None,
        # int __fwriting (FILE *STREAM);
        "__fwriting": None,
        # int fclose (FILE *STREAM);
        "fclose": None,
        # int fcloseall (void);
        "fcloseall": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # void flockfile (FILE *STREAM);
        "flockfile": None,
        # int ftrylockfile (FILE *STREAM);
        "ftrylockfile": None,
        # void funlockfile (FILE *STREAM);
        "funlockfile": None,
        # int __fsetlocking (FILE *STREAM, int TYPE);
        "__fsetlocking": None,
        # int fwide (FILE *STREAM, int MODE);
        "fwide": None,
        # int fputc (int C, FILE *STREAM);
        "fputc": None,
        # wint_t fputwc (wchar_t WC, FILE *STREAM);
        "fputwc": None,
        # int fputc_unlocked (int C, FILE *STREAM);
        "fputc_unlocked": None,
        # wint_t fputwc_unlocked (wchar_t WC, FILE *STREAM);
        "fputwc_unlocked": None,
        # int putc (int C, FILE *STREAM);
        "putc": None,
        # wint_t putwc (wchar_t WC, FILE *STREAM);
        "putwc": None,
        # int putc_unlocked (int C, FILE *STREAM);
        "putc_unlocked": None,
        # wint_t putwc_unlocked (wchar_t WC, FILE *STREAM);
        "putwc_unlocked": None,
        # int putchar (int C);
        "putchar": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # wint_t putwchar (wchar_t WC);
        "putwchar": None,
        # int putchar_unlocked (int C);
        "putchar_unlocked": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # wint_t putwchar_unlocked (wchar_t WC);
        "putwchar_unlocked": None,
        # int fputs (const char *S, FILE *STREAM);
        "fputs": None,
        # int fputws (const wchar_t *WS, FILE *STREAM);
        "fputws": None,
        # int fputs_unlocked (const char *S, FILE *STREAM);
        "fputs_unlocked": None,
        # int fputws_unlocked (const wchar_t *WS, FILE *STREAM);
        "fputws_unlocked": None,
        # int puts (const char *S);
        "puts": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int putw (int W, FILE *STREAM);
        "putw": None,
        # int fgetc (FILE *STREAM);
        "fgetc": None,
        # wint_t fgetwc (FILE *STREAM);
        "fgetwc": None,
        # int fgetc_unlocked (FILE *STREAM);
        "fgetc_unlocked": None,
        # wint_t fgetwc_unlocked (FILE *STREAM);
        "fgetwc_unlocked": None,
        # int getc (FILE *STREAM);
        "getc": None,
        # wint_t getwc (FILE *STREAM);
        "getwc": None,
        # int getc_unlocked (FILE *STREAM);
        "getc_unlocked": None,
        # wint_t getwc_unlocked (FILE *STREAM);
        "getwc_unlocked": None,
        # int getchar (void);
        "getchar": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # wint_t getwchar (void);
        "getwchar": None,
        # int getchar_unlocked (void);
        "getchar_unlocked": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # wint_t getwchar_unlocked (void);
        "getwchar_unlocked": None,
        # int getw (FILE *STREAM);
        "getw": None,
        # ssize_t getline (char **LINEPTR, size_t *N, FILE *STREAM);
        "getline": None,
        # ssize_t getdelim (char **LINEPTR, size_t *N, int DELIMITER, FILE *STREAM);
        "getdelim": None,
        # char * fgets (char *S, int COUNT, FILE *STREAM);
        "fgets": None,
        # wchar_t * fgetws (wchar_t *WS, int COUNT, FILE *STREAM);
        "fgetws": None,
        # char * fgets_unlocked (char *S, int COUNT, FILE *STREAM);
        "fgets_unlocked": None,
        # wchar_t * fgetws_unlocked (wchar_t *WS, int COUNT, FILE *STREAM);
        "fgetws_unlocked": None,
        # int ungetc (int C, FILE *STREAM);
        "ungetc": None,
        # wint_t ungetwc (wint_t WC, FILE *STREAM);
        "ungetwc": None,
        # size_t fread (void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);
        "fread": None,
        # size_t fread_unlocked (void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);
        "fread_unlocked": None,
        # size_t fwrite (const void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);
        "fwrite": None,
        # size_t fwrite_unlocked (const void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);
        "fwrite_unlocked": None,
        # int printf (const char *TEMPLATE, ...);
        "printf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int wprintf (const wchar_t *TEMPLATE, ...);
        "wprintf": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int fprintf (FILE *STREAM, const char *TEMPLATE, ...);
        "fprintf": None,
        # int fwprintf (FILE *STREAM, const wchar_t *TEMPLATE, ...);
        "fwprintf": None,
        # int sprintf (char *S, const char *TEMPLATE, ...);
        "sprintf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int swprintf (wchar_t *WS, size_t SIZE, const wchar_t *TEMPLATE, ...);
        "swprintf": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int snprintf (char *S, size_t SIZE, const char *TEMPLATE, ...);
        "snprintf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int asprintf (char **PTR, const char *TEMPLATE, ...);
        "asprintf": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int obstack_printf (struct obstack *OBSTACK, const char *TEMPLATE, ...);
        "obstack_printf": SimTypeFunction([SimTypePointer(SimStruct({}, name="obstack", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int vprintf (const char *TEMPLATE, va_list AP);
        "vprintf": None,
        # int vwprintf (const wchar_t *TEMPLATE, va_list AP);
        "vwprintf": None,
        # int vfprintf (FILE *STREAM, const char *TEMPLATE, va_list AP);
        "vfprintf": None,
        # int vfwprintf (FILE *STREAM, const wchar_t *TEMPLATE, va_list AP);
        "vfwprintf": None,
        # int vsprintf (char *S, const char *TEMPLATE, va_list AP);
        "vsprintf": None,
        # int vswprintf (wchar_t *WS, size_t SIZE, const wchar_t *TEMPLATE, va_list AP);
        "vswprintf": None,
        # int vsnprintf (char *S, size_t SIZE, const char *TEMPLATE, va_list AP);
        "vsnprintf": None,
        # int vasprintf (char **PTR, const char *TEMPLATE, va_list AP);
        "vasprintf": None,
        # int obstack_vprintf (struct obstack *OBSTACK, const char *TEMPLATE, va_list AP);
        "obstack_vprintf": None,
        # size_t parse_printf_format (const char *TEMPLATE, size_t N, int *ARGTYPES);
        "parse_printf_format": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # int register_printf_function (int SPEC, printf_function HANDLER_FUNCTION, printf_arginfo_function ARGINFO_FUNCTION);
        "register_printf_function": None,
        # int printf_size (FILE *FP, const struct printf_info *INFO, const void *const *ARGS);
        "printf_size": None,
        # int printf_size_info (const struct printf_info *INFO, size_t N, int *ARGTYPES);
        "printf_size_info": SimTypeFunction([SimTypePointer(SimStruct({}, name="printf_info", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int scanf (const char *TEMPLATE, ...);
        "scanf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int wscanf (const wchar_t *TEMPLATE, ...);
        "wscanf": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int fscanf (FILE *STREAM, const char *TEMPLATE, ...);
        "fscanf": None,
        # int fwscanf (FILE *STREAM, const wchar_t *TEMPLATE, ...);
        "fwscanf": None,
        # int sscanf (const char *S, const char *TEMPLATE, ...);
        "sscanf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int swscanf (const wchar_t *WS, const wchar_t *TEMPLATE, ...);
        "swscanf": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int vscanf (const char *TEMPLATE, va_list AP);
        "vscanf": None,
        # int vwscanf (const wchar_t *TEMPLATE, va_list AP);
        "vwscanf": None,
        # int vfscanf (FILE *STREAM, const char *TEMPLATE, va_list AP);
        "vfscanf": None,
        # int vfwscanf (FILE *STREAM, const wchar_t *TEMPLATE, va_list AP);
        "vfwscanf": None,
        # int vsscanf (const char *S, const char *TEMPLATE, va_list AP);
        "vsscanf": None,
        # int vswscanf (const wchar_t *S, const wchar_t *TEMPLATE, va_list AP);
        "vswscanf": None,
        # int feof (FILE *STREAM);
        "feof": None,
        # int feof_unlocked (FILE *STREAM);
        "feof_unlocked": None,
        # int ferror (FILE *STREAM);
        "ferror": None,
        # int ferror_unlocked (FILE *STREAM);
        "ferror_unlocked": None,
        # void clearerr (FILE *STREAM);
        "clearerr": None,
        # void clearerr_unlocked (FILE *STREAM);
        "clearerr_unlocked": None,
        # long int ftell (FILE *STREAM);
        "ftell": None,
        # off_t ftello (FILE *STREAM);
        "ftello": None,
        # off64_t ftello64 (FILE *STREAM);
        "ftello64": None,
        # int fseek (FILE *STREAM, long int OFFSET, int WHENCE);
        "fseek": None,
        # int fseeko (FILE *STREAM, off_t OFFSET, int WHENCE);
        "fseeko": None,
        # int fseeko64 (FILE *STREAM, off64_t OFFSET, int WHENCE);
        "fseeko64": None,
        # void rewind (FILE *STREAM);
        "rewind": None,
        # int fgetpos (FILE *STREAM, fpos_t *POSITION);
        "fgetpos": None,
        # int fgetpos64 (FILE *STREAM, fpos64_t *POSITION);
        "fgetpos64": None,
        # int fsetpos (FILE *STREAM, const fpos_t *POSITION);
        "fsetpos": None,
        # int fsetpos64 (FILE *STREAM, const fpos64_t *POSITION);
        "fsetpos64": None,
        # int fflush (FILE *STREAM);
        "fflush": None,
        # int fflush_unlocked (FILE *STREAM);
        "fflush_unlocked": None,
        # void _flushlbf (void);
        "_flushlbf": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __fpurge (FILE *STREAM);
        "__fpurge": None,
        # int setvbuf (FILE *STREAM, char *BUF, int MODE, size_t SIZE);
        "setvbuf": None,
        # void setbuf (FILE *STREAM, char *BUF);
        "setbuf": None,
        # void setbuffer (FILE *STREAM, char *BUF, size_t SIZE);
        "setbuffer": None,
        # void setlinebuf (FILE *STREAM);
        "setlinebuf": None,
        # int __flbf (FILE *STREAM);
        "__flbf": None,
        # size_t __fbufsize (FILE *STREAM);
        "__fbufsize": None,
        # size_t __fpending (FILE *STREAM);
        "__fpending": None,
        # FILE * fmemopen (void *BUF, size_t SIZE, const char *OPENTYPE);
        "fmemopen": None,
        # FILE * open_memstream (char **PTR, size_t *SIZELOC);
        "open_memstream": None,
        # FILE * fopencookie (void *COOKIE, const char *OPENTYPE, cookie_io_functions_t IO-FUNCTIONS);
        "fopencookie": None,
        # int fmtmsg (long int CLASSIFICATION, const char *LABEL, int SEVERITY, const char *TEXT, const char *ACTION, const char *TAG);
        "fmtmsg": SimTypeFunction([SimTypeLong(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int addseverity (int SEVERITY, const char *STRING);
        "addseverity": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int open (const char *FILENAME, int FLAGS, mode_t MODE);
        "open": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int open64 (const char *FILENAME, int FLAGS, mode_t MODE);
        "open64": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int close (int FILEDES);
        "close": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # ssize_t read (int FILEDES, void *BUFFER, size_t SIZE);
        "read": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pread (int FILEDES, void *BUFFER, size_t SIZE, off_t OFFSET);
        "pread": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pread64 (int FILEDES, void *BUFFER, size_t SIZE, off64_t OFFSET);
        "pread64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t write (int FILEDES, const void *BUFFER, size_t SIZE);
        "write": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwrite (int FILEDES, const void *BUFFER, size_t SIZE, off_t OFFSET);
        "pwrite": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwrite64 (int FILEDES, const void *BUFFER, size_t SIZE, off64_t OFFSET);
        "pwrite64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t preadv (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET);
        "preadv": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t preadv64 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET);
        "preadv64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwritev (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET);
        "pwritev": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwritev64 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET);
        "pwritev64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t preadv2 (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET, int FLAGS);
        "preadv2": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t preadv64v2 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET, int FLAGS);
        "preadv64v2": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwritev2 (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET, int FLAGS);
        "pwritev2": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t pwritev64v2 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET, int FLAGS);
        "pwritev64v2": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # off_t lseek (int FILEDES, off_t OFFSET, int WHENCE);
        "lseek": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # off64_t lseek64 (int FILEDES, off64_t OFFSET, int WHENCE);
        "lseek64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=False, label=None), label=None),
        # FILE * fdopen (int FILEDES, const char *OPENTYPE);
        "fdopen": None,
        # int fileno (FILE *STREAM);
        "fileno": None,
        # int fileno_unlocked (FILE *STREAM);
        "fileno_unlocked": None,
        # ssize_t readv (int FILEDES, const struct iovec *VECTOR, int COUNT);
        "readv": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t writev (int FILEDES, const struct iovec *VECTOR, int COUNT);
        "writev": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="iovec", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # void * mmap (void *ADDRESS, size_t LENGTH, int PROTECT, int FLAGS, int FILEDES, off_t OFFSET);
        "mmap": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # void * mmap64 (void *ADDRESS, size_t LENGTH, int PROTECT, int FLAGS, int FILEDES, off64_t OFFSET);
        "mmap64": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int munmap (void *ADDR, size_t LENGTH);
        "munmap": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int msync (void *ADDRESS, size_t LENGTH, int FLAGS);
        "msync": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void * mremap (void *ADDRESS, size_t LENGTH, size_t NEW_LENGTH, int FLAG);
        "mremap": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None),
        # int madvise (void *ADDR, size_t LENGTH, int ADVICE);
        "madvise": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int shm_open (const char *NAME, int OFLAG, mode_t MODE);
        "shm_open": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int shm_unlink (const char *NAME);
        "shm_unlink": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int select (int NFDS, fd_set *READ_FDS, fd_set *WRITE_FDS, fd_set *EXCEPT_FDS, struct timeval *TIMEOUT);
        "select": None,
        # void sync (void);
        "sync": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int fsync (int FILDES);
        "fsync": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fdatasync (int FILDES);
        "fdatasync": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_read (struct aiocb *AIOCBP);
        "aio_read": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_read64 (struct aiocb64 *AIOCBP);
        "aio_read64": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_write (struct aiocb *AIOCBP);
        "aio_write": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_write64 (struct aiocb64 *AIOCBP);
        "aio_write64": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lio_listio (int MODE, struct aiocb *const LIST[], int NENT, struct sigevent *SIG);
        "lio_listio": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeFixedSizeArray(SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0), 0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sigevent", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lio_listio64 (int MODE, struct aiocb64 *const LIST[], int NENT, struct sigevent *SIG);
        "lio_listio64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeFixedSizeArray(SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0), 0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sigevent", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_error (const struct aiocb *AIOCBP);
        "aio_error": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_error64 (const struct aiocb64 *AIOCBP);
        "aio_error64": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # ssize_t aio_return (struct aiocb *AIOCBP);
        "aio_return": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t aio_return64 (struct aiocb64 *AIOCBP);
        "aio_return64": SimTypeFunction([SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # int aio_fsync (int OP, struct aiocb *AIOCBP);
        "aio_fsync": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_fsync64 (int OP, struct aiocb64 *AIOCBP);
        "aio_fsync64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_suspend (const struct aiocb *const LIST[], int NENT, const struct timespec *TIMEOUT);
        "aio_suspend": SimTypeFunction([SimTypeFixedSizeArray(SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0), 0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="timespec", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_suspend64 (const struct aiocb64 *const LIST[], int NENT, const struct timespec *TIMEOUT);
        "aio_suspend64": SimTypeFunction([SimTypeFixedSizeArray(SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0), 0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="timespec", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_cancel (int FILDES, struct aiocb *AIOCBP);
        "aio_cancel": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="aiocb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int aio_cancel64 (int FILDES, struct aiocb64 *AIOCBP);
        "aio_cancel64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="aiocb64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void aio_init (const struct aioinit *INIT);
        "aio_init": SimTypeFunction([SimTypePointer(SimStruct({}, name="aioinit", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int fcntl (int FILEDES, int COMMAND, ...);
        "fcntl": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int dup (int OLD);
        "dup": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int dup2 (int OLD, int NEW);
        "dup2": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int ioctl (int FILEDES, int COMMAND, ...);
        "ioctl": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # char * getcwd (char *BUFFER, size_t SIZE);
        "getcwd": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * get_current_dir_name (void);
        "get_current_dir_name": SimTypeFunction([ ], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int chdir (const char *FILENAME);
        "chdir": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int fchdir (int FILEDES);
        "fchdir": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int IFTODT (mode_t MODE);
        "IFTODT": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # mode_t DTTOIF (int DTYPE);
        "DTTOIF": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # DIR * opendir (const char *DIRNAME);
        "opendir": None,
        # DIR * fdopendir (int FD);
        "fdopendir": None,
        # int dirfd (DIR *DIRSTREAM);
        "dirfd": None,
        # struct dirent * readdir (DIR *DIRSTREAM);
        "readdir": None,
        # int readdir_r (DIR *DIRSTREAM, struct dirent *ENTRY, struct dirent **RESULT);
        "readdir_r": None,
        # struct dirent64 * readdir64 (DIR *DIRSTREAM);
        "readdir64": None,
        # int readdir64_r (DIR *DIRSTREAM, struct dirent64 *ENTRY, struct dirent64 **RESULT);
        "readdir64_r": None,
        # int closedir (DIR *DIRSTREAM);
        "closedir": None,
        # void rewinddir (DIR *DIRSTREAM);
        "rewinddir": None,
        # long int telldir (DIR *DIRSTREAM);
        "telldir": None,
        # void seekdir (DIR *DIRSTREAM, long int POS);
        "seekdir": None,
        # int scandir (const char *DIR, struct dirent ***NAMELIST, int (*SELECTOR);
        "scandir": None,
        # int alphasort (const struct dirent **A, const struct dirent **B);
        "alphasort": SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({}, name="dirent", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="dirent", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int versionsort (const struct dirent **A, const struct dirent **B);
        "versionsort": SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({}, name="dirent", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="dirent", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int scandir64 (const char *DIR, struct dirent64 ***NAMELIST, int (*SELECTOR);
        "scandir64": None,
        # int alphasort64 (const struct dirent64 **A, const struct dirent **B);
        "alphasort64": SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({}, name="dirent64", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="dirent", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int versionsort64 (const struct dirent64 **A, const struct dirent64 **B);
        "versionsort64": SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({}, name="dirent64", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="dirent64", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int ftw (const char *FILENAME, __ftw_func_t FUNC, int DESCRIPTORS);
        "ftw": None,
        # int ftw64 (const char *FILENAME, __ftw64_func_t FUNC, int DESCRIPTORS);
        "ftw64": None,
        # int nftw (const char *FILENAME, __nftw_func_t FUNC, int DESCRIPTORS, int FLAG);
        "nftw": None,
        # int nftw64 (const char *FILENAME, __nftw64_func_t FUNC, int DESCRIPTORS, int FLAG);
        "nftw64": None,
        # int link (const char *OLDNAME, const char *NEWNAME);
        "link": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int symlink (const char *OLDNAME, const char *NEWNAME);
        "symlink": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # ssize_t readlink (const char *FILENAME, char *BUFFER, size_t SIZE);
        "readlink": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # char * canonicalize_file_name (const char *NAME);
        "canonicalize_file_name": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * realpath (const char *restrict NAME, char *restrict RESOLVED);
        "realpath": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int unlink (const char *FILENAME);
        "unlink": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int rmdir (const char *FILENAME);
        "rmdir": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int remove (const char *FILENAME);
        "remove": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int rename (const char *OLDNAME, const char *NEWNAME);
        "rename": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int mkdir (const char *FILENAME, mode_t MODE);
        "mkdir": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int stat (const char *FILENAME, struct stat *BUF);
        "stat": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="stat", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int stat64 (const char *FILENAME, struct stat64 *BUF);
        "stat64": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="stat64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int fstat (int FILEDES, struct stat *BUF);
        "fstat": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="stat", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int fstat64 (int FILEDES, struct stat64 *BUF);
        "fstat64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="stat64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lstat (const char *FILENAME, struct stat *BUF);
        "lstat": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="stat", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lstat64 (const char *FILENAME, struct stat64 *BUF);
        "lstat64": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="stat64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int chown (const char *FILENAME, uid_t OWNER, gid_t GROUP);
        "chown": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fchown (int FILEDES, uid_t OWNER, gid_t GROUP);
        "fchown": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # mode_t umask (mode_t MASK);
        "umask": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # mode_t getumask (void);
        "getumask": SimTypeFunction([ ], SimTypeInt(signed=False, label=None), label=None),
        # int chmod (const char *FILENAME, mode_t MODE);
        "chmod": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fchmod (int FILEDES, mode_t MODE);
        "fchmod": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int access (const char *FILENAME, int HOW);
        "access": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int utime (const char *FILENAME, const struct utimbuf *TIMES);
        "utime": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="utimbuf", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int utimes (const char *FILENAME, const struct timeval TVP[2]);
        "utimes": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFixedSizeArray(SimStruct({}, name="timeval", pack=True), 2)], SimTypeInt(signed=True, label=None), label=None),
        # int lutimes (const char *FILENAME, const struct timeval TVP[2]);
        "lutimes": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFixedSizeArray(SimStruct({}, name="timeval", pack=True), 2)], SimTypeInt(signed=True, label=None), label=None),
        # int futimes (int FD, const struct timeval TVP[2]);
        "futimes": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeFixedSizeArray(SimStruct({}, name="timeval", pack=True), 2)], SimTypeInt(signed=True, label=None), label=None),
        # int truncate (const char *FILENAME, off_t LENGTH);
        "truncate": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int truncate64 (const char *NAME, off64_t LENGTH);
        "truncate64": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLongLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int ftruncate (int FD, off_t LENGTH);
        "ftruncate": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int ftruncate64 (int ID, off64_t LENGTH);
        "ftruncate64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int posix_fallocate (int FD, off_t OFFSET, off_t LENGTH);
        "posix_fallocate": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int posix_fallocate64 (int FD, off64_t OFFSET, off64_t LENGTH);
        "posix_fallocate64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeLongLong(signed=False, label=None), SimTypeLongLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int mknod (const char *FILENAME, mode_t MODE, dev_t DEV);
        "mknod": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # FILE * tmpfile (void);
        "tmpfile": None,
        # FILE * tmpfile64 (void);
        "tmpfile64": None,
        # char * tmpnam (char *RESULT);
        "tmpnam": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * tmpnam_r (char *RESULT);
        "tmpnam_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * tempnam (const char *DIR, const char *PREFIX);
        "tempnam": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * mktemp (char *TEMPLATE);
        "mktemp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int mkstemp (char *TEMPLATE);
        "mkstemp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # char * mkdtemp (char *TEMPLATE);
        "mkdtemp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int pipe (int FILEDES[2]);
        "pipe": SimTypeFunction([SimTypeFixedSizeArray(SimTypeInt(signed=True, label=None), 2)], SimTypeInt(signed=True, label=None), label=None),
        # FILE * popen (const char *COMMAND, const char *MODE);
        "popen": None,
        # int pclose (FILE *STREAM);
        "pclose": None,
        # int mkfifo (const char *FILENAME, mode_t MODE);
        "mkfifo": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int bind (int SOCKET, struct sockaddr *ADDR, socklen_t LENGTH);
        "bind": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int getsockname (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);
        "getsockname": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # unsigned int if_nametoindex (const char *IFNAME);
        "if_nametoindex": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=False, label=None), label=None),
        # char * if_indextoname (unsigned int IFINDEX, char *IFNAME);
        "if_indextoname": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # struct if_nameindex * if_nameindex (void);
        "if_nameindex": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="if_nameindex", pack=True), label=None, offset=0), label=None),
        # void if_freenameindex (struct if_nameindex *PTR);
        "if_freenameindex": SimTypeFunction([SimTypePointer(SimStruct({}, name="if_nameindex", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int inet_aton (const char *NAME, struct in_addr *ADDR);
        "inet_aton": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="in_addr", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # uint32_t inet_addr (const char *NAME);
        "inet_addr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=False, label=None), label=None),
        # uint32_t inet_network (const char *NAME);
        "inet_network": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=False, label=None), label=None),
        # char * inet_ntoa (struct in_addr ADDR);
        "inet_ntoa": SimTypeFunction([SimStruct({}, name="in_addr", pack=True)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # struct in_addr inet_makeaddr (uint32_t NET, uint32_t LOCAL);
        "inet_makeaddr": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypeInt(signed=False, label=None)], SimStruct({}, name="in_addr", pack=True), label=None),
        # uint32_t inet_lnaof (struct in_addr ADDR);
        "inet_lnaof": SimTypeFunction([SimStruct({}, name="in_addr", pack=True)], SimTypeInt(signed=False, label=None), label=None),
        # uint32_t inet_netof (struct in_addr ADDR);
        "inet_netof": SimTypeFunction([SimStruct({}, name="in_addr", pack=True)], SimTypeInt(signed=False, label=None), label=None),
        # int inet_pton (int AF, const char *CP, void *BUF);
        "inet_pton": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # const char * inet_ntop (int AF, const void *CP, char *BUF, socklen_t LEN);
        "inet_ntop": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # struct hostent * gethostbyname (const char *NAME);
        "gethostbyname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None),
        # struct hostent * gethostbyname2 (const char *NAME, int AF);
        "gethostbyname2": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None),
        # struct hostent * gethostbyaddr (const void *ADDR, socklen_t LENGTH, int FORMAT);
        "gethostbyaddr": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None),
        # int gethostbyname_r (const char *restrict NAME, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent **restrict RESULT, int * restrict H_ERRNOP);
        "gethostbyname_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int gethostbyname2_r (const char *NAME, int AF, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent **restrict RESULT, int * restrict H_ERRNOP);
        "gethostbyname2_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int gethostbyaddr_r (const void *ADDR, socklen_t LENGTH, int FORMAT, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent ** restrict RESULT, int * restrict H_ERRNOP);
        "gethostbyaddr_r": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void sethostent (int STAYOPEN);
        "sethostent": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # struct hostent * gethostent (void);
        "gethostent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="hostent", pack=True), label=None, offset=0), label=None),
        # void endhostent (void);
        "endhostent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct servent * getservbyname (const char *NAME, const char *PROTO);
        "getservbyname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="servent", pack=True), label=None, offset=0), label=None),
        # struct servent * getservbyport (int PORT, const char *PROTO);
        "getservbyport": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="servent", pack=True), label=None, offset=0), label=None),
        # void setservent (int STAYOPEN);
        "setservent": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # struct servent * getservent (void);
        "getservent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="servent", pack=True), label=None, offset=0), label=None),
        # void endservent (void);
        "endservent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # uint16_t htons (uint16_t HOSTSHORT);
        "htons": SimTypeFunction([SimTypeShort(signed=False, label=None)], SimTypeShort(signed=False, label=None), label=None),
        # uint16_t ntohs (uint16_t NETSHORT);
        "ntohs": SimTypeFunction([SimTypeShort(signed=False, label=None)], SimTypeShort(signed=False, label=None), label=None),
        # uint32_t htonl (uint32_t HOSTLONG);
        "htonl": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # uint32_t ntohl (uint32_t NETLONG);
        "ntohl": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # struct protoent * getprotobyname (const char *NAME);
        "getprotobyname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="protoent", pack=True), label=None, offset=0), label=None),
        # struct protoent * getprotobynumber (int PROTOCOL);
        "getprotobynumber": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypePointer(SimStruct({}, name="protoent", pack=True), label=None, offset=0), label=None),
        # void setprotoent (int STAYOPEN);
        "setprotoent": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # struct protoent * getprotoent (void);
        "getprotoent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="protoent", pack=True), label=None, offset=0), label=None),
        # void endprotoent (void);
        "endprotoent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int socket (int NAMESPACE, int STYLE, int PROTOCOL);
        "socket": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int shutdown (int SOCKET, int HOW);
        "shutdown": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int socketpair (int NAMESPACE, int STYLE, int PROTOCOL, int FILEDES[2]);
        "socketpair": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeFixedSizeArray(SimTypeInt(signed=True, label=None), 2)], SimTypeInt(signed=True, label=None), label=None),
        # int connect (int SOCKET, struct sockaddr *ADDR, socklen_t LENGTH);
        "connect": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int listen (int SOCKET, int N);
        "listen": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int accept (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);
        "accept": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getpeername (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);
        "getpeername": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # ssize_t send (int SOCKET, const void *BUFFER, size_t SIZE, int FLAGS);
        "send": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t recv (int SOCKET, void *BUFFER, size_t SIZE, int FLAGS);
        "recv": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t sendto (int SOCKET, const void *BUFFER, size_t SIZE, int FLAGS, struct sockaddr *ADDR, socklen_t LENGTH);
        "sendto": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # ssize_t recvfrom (int SOCKET, void *BUFFER, size_t SIZE, int FLAGS, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);
        "recvfrom": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sockaddr", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # int getsockopt (int SOCKET, int LEVEL, int OPTNAME, void *OPTVAL, socklen_t *OPTLEN_PTR);
        "getsockopt": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setsockopt (int SOCKET, int LEVEL, int OPTNAME, const void *OPTVAL, socklen_t OPTLEN);
        "setsockopt": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # struct netent * getnetbyname (const char *NAME);
        "getnetbyname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="netent", pack=True), label=None, offset=0), label=None),
        # struct netent * getnetbyaddr (uint32_t NET, int TYPE);
        "getnetbyaddr": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypeInt(signed=True, label=None)], SimTypePointer(SimStruct({}, name="netent", pack=True), label=None, offset=0), label=None),
        # void setnetent (int STAYOPEN);
        "setnetent": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # struct netent * getnetent (void);
        "getnetent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="netent", pack=True), label=None, offset=0), label=None),
        # void endnetent (void);
        "endnetent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int isatty (int FILEDES);
        "isatty": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # char * ttyname (int FILEDES);
        "ttyname": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int ttyname_r (int FILEDES, char *BUF, size_t LEN);
        "ttyname_r": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int tcgetattr (int FILEDES, struct termios *TERMIOS_P);
        "tcgetattr": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="termios", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int tcsetattr (int FILEDES, int WHEN, const struct termios *TERMIOS_P);
        "tcsetattr": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="termios", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # speed_t cfgetospeed (const struct termios *TERMIOS_P);
        "cfgetospeed": None,
        # speed_t cfgetispeed (const struct termios *TERMIOS_P);
        "cfgetispeed": None,
        # int cfsetospeed (struct termios *TERMIOS_P, speed_t SPEED);
        "cfsetospeed": None,
        # int cfsetispeed (struct termios *TERMIOS_P, speed_t SPEED);
        "cfsetispeed": None,
        # int cfsetspeed (struct termios *TERMIOS_P, speed_t SPEED);
        "cfsetspeed": None,
        # void cfmakeraw (struct termios *TERMIOS_P);
        "cfmakeraw": SimTypeFunction([SimTypePointer(SimStruct({}, name="termios", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int gtty (int FILEDES, struct sgttyb *ATTRIBUTES);
        "gtty": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sgttyb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int stty (int FILEDES, const struct sgttyb *ATTRIBUTES);
        "stty": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sgttyb", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int tcsendbreak (int FILEDES, int DURATION);
        "tcsendbreak": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int tcdrain (int FILEDES);
        "tcdrain": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int tcflush (int FILEDES, int QUEUE);
        "tcflush": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int tcflow (int FILEDES, int ACTION);
        "tcflow": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int getpt (void);
        "getpt": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int grantpt (int FILEDES);
        "grantpt": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int unlockpt (int FILEDES);
        "unlockpt": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # char * ptsname (int FILEDES);
        "ptsname": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int ptsname_r (int FILEDES, char *BUF, size_t LEN);
        "ptsname_r": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int openpty (int *AMASTER, int *ASLAVE, char *NAME, const struct termios *TERMP, const struct winsize *WINP);
        "openpty": SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="termios", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="winsize", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int forkpty (int *AMASTER, char *NAME, const struct termios *TERMP, const struct winsize *WINP);
        "forkpty": SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="termios", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="winsize", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void openlog (const char *IDENT, int OPTION, int FACILITY);
        "openlog": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void syslog (int FACILITY_PRIORITY, const char *FORMAT, ...);
        "syslog": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void vsyslog (int FACILITY_PRIORITY, const char *FORMAT, va_list ARGLIST);
        "vsyslog": None,
        # void closelog (void);
        "closelog": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int setlogmask (int MASK);
        "setlogmask": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # double sin (double X);
        "sin": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float sinf (float X);
        "sinf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double sinl (long double X);
        "sinl": None,
        # _FloatN sinfN (_FloatN X);
        "sinfN": None,
        # _FloatNx sinfNx (_FloatNx X);
        "sinfNx": None,
        # double cos (double X);
        "cos": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float cosf (float X);
        "cosf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double cosl (long double X);
        "cosl": None,
        # _FloatN cosfN (_FloatN X);
        "cosfN": None,
        # _FloatNx cosfNx (_FloatNx X);
        "cosfNx": None,
        # double tan (double X);
        "tan": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float tanf (float X);
        "tanf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double tanl (long double X);
        "tanl": None,
        # _FloatN tanfN (_FloatN X);
        "tanfN": None,
        # _FloatNx tanfNx (_FloatNx X);
        "tanfNx": None,
        # void sincos (double X, double *SINX, double *COSX);
        "sincos": SimTypeFunction([SimTypeDouble(), SimTypePointer(SimTypeDouble(), label=None, offset=0), SimTypePointer(SimTypeDouble(), label=None, offset=0)], SimTypeBottom(), label=None),
        # void sincosf (float X, float *SINX, float *COSX);
        "sincosf": SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=32), label=None, offset=0), SimTypePointer(SimTypeFloat(size=32), label=None, offset=0)], SimTypeBottom(), label=None),
        # void sincosl (long double X, long double *SINX, long double *COSX);
        "sincosl": None,
        # _FloatN sincosfN (_FloatN X, _FloatN *SINX, _FloatN *COSX);
        "sincosfN": None,
        # _FloatNx sincosfNx (_FloatNx X, _FloatNx *SINX, _FloatNx *COSX);
        "sincosfNx": None,
        # complex double csin (complex double Z);
        "csin": None,
        # complex float csinf (complex float Z);
        "csinf": None,
        # complex long double csinl (complex long double Z);
        "csinl": None,
        # complex _FloatN csinfN (complex _FloatN Z);
        "csinfN": None,
        # complex _FloatNx csinfNx (complex _FloatNx Z);
        "csinfNx": None,
        # complex double ccos (complex double Z);
        "ccos": None,
        # complex float ccosf (complex float Z);
        "ccosf": None,
        # complex long double ccosl (complex long double Z);
        "ccosl": None,
        # complex _FloatN ccosfN (complex _FloatN Z);
        "ccosfN": None,
        # complex _FloatNx ccosfNx (complex _FloatNx Z);
        "ccosfNx": None,
        # complex double ctan (complex double Z);
        "ctan": None,
        # complex float ctanf (complex float Z);
        "ctanf": None,
        # complex long double ctanl (complex long double Z);
        "ctanl": None,
        # complex _FloatN ctanfN (complex _FloatN Z);
        "ctanfN": None,
        # complex _FloatNx ctanfNx (complex _FloatNx Z);
        "ctanfNx": None,
        # double asin (double X);
        "asin": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float asinf (float X);
        "asinf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double asinl (long double X);
        "asinl": None,
        # _FloatN asinfN (_FloatN X);
        "asinfN": None,
        # _FloatNx asinfNx (_FloatNx X);
        "asinfNx": None,
        # double acos (double X);
        "acos": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float acosf (float X);
        "acosf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double acosl (long double X);
        "acosl": None,
        # _FloatN acosfN (_FloatN X);
        "acosfN": None,
        # _FloatNx acosfNx (_FloatNx X);
        "acosfNx": None,
        # double atan (double X);
        "atan": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float atanf (float X);
        "atanf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double atanl (long double X);
        "atanl": None,
        # _FloatN atanfN (_FloatN X);
        "atanfN": None,
        # _FloatNx atanfNx (_FloatNx X);
        "atanfNx": None,
        # double atan2 (double Y, double X);
        "atan2": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float atan2f (float Y, float X);
        "atan2f": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double atan2l (long double Y, long double X);
        "atan2l": None,
        # _FloatN atan2fN (_FloatN Y, _FloatN X);
        "atan2fN": None,
        # _FloatNx atan2fNx (_FloatNx Y, _FloatNx X);
        "atan2fNx": None,
        # complex double casin (complex double Z);
        "casin": None,
        # complex float casinf (complex float Z);
        "casinf": None,
        # complex long double casinl (complex long double Z);
        "casinl": None,
        # complex _FloatN casinfN (complex _FloatN Z);
        "casinfN": None,
        # complex _FloatNx casinfNx (complex _FloatNx Z);
        "casinfNx": None,
        # complex double cacos (complex double Z);
        "cacos": None,
        # complex float cacosf (complex float Z);
        "cacosf": None,
        # complex long double cacosl (complex long double Z);
        "cacosl": None,
        # complex _FloatN cacosfN (complex _FloatN Z);
        "cacosfN": None,
        # complex _FloatNx cacosfNx (complex _FloatNx Z);
        "cacosfNx": None,
        # complex double catan (complex double Z);
        "catan": None,
        # complex float catanf (complex float Z);
        "catanf": None,
        # complex long double catanl (complex long double Z);
        "catanl": None,
        # complex _FloatN catanfN (complex _FloatN Z);
        "catanfN": None,
        # complex _FloatNx catanfNx (complex _FloatNx Z);
        "catanfNx": None,
        # double exp (double X);
        "exp": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float expf (float X);
        "expf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double expl (long double X);
        "expl": None,
        # _FloatN expfN (_FloatN X);
        "expfN": None,
        # _FloatNx expfNx (_FloatNx X);
        "expfNx": None,
        # double exp2 (double X);
        "exp2": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float exp2f (float X);
        "exp2f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double exp2l (long double X);
        "exp2l": None,
        # _FloatN exp2fN (_FloatN X);
        "exp2fN": None,
        # _FloatNx exp2fNx (_FloatNx X);
        "exp2fNx": None,
        # double exp10 (double X);
        "exp10": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float exp10f (float X);
        "exp10f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double exp10l (long double X);
        "exp10l": None,
        # _FloatN exp10fN (_FloatN X);
        "exp10fN": None,
        # _FloatNx exp10fNx (_FloatNx X);
        "exp10fNx": None,
        # double pow10 (double X);
        "pow10": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float pow10f (float X);
        "pow10f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double pow10l (long double X);
        "pow10l": None,
        # double log (double X);
        "log": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float logf (float X);
        "logf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double logl (long double X);
        "logl": None,
        # _FloatN logfN (_FloatN X);
        "logfN": None,
        # _FloatNx logfNx (_FloatNx X);
        "logfNx": None,
        # double log10 (double X);
        "log10": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float log10f (float X);
        "log10f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double log10l (long double X);
        "log10l": None,
        # _FloatN log10fN (_FloatN X);
        "log10fN": None,
        # _FloatNx log10fNx (_FloatNx X);
        "log10fNx": None,
        # double log2 (double X);
        "log2": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float log2f (float X);
        "log2f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double log2l (long double X);
        "log2l": None,
        # _FloatN log2fN (_FloatN X);
        "log2fN": None,
        # _FloatNx log2fNx (_FloatNx X);
        "log2fNx": None,
        # double logb (double X);
        "logb": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float logbf (float X);
        "logbf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double logbl (long double X);
        "logbl": None,
        # _FloatN logbfN (_FloatN X);
        "logbfN": None,
        # _FloatNx logbfNx (_FloatNx X);
        "logbfNx": None,
        # int ilogb (double X);
        "ilogb": SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int ilogbf (float X);
        "ilogbf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int ilogbl (long double X);
        "ilogbl": None,
        # int ilogbfN (_FloatN X);
        "ilogbfN": None,
        # int ilogbfNx (_FloatNx X);
        "ilogbfNx": None,
        # long int llogb (double X);
        "llogb": SimTypeFunction([SimTypeDouble()], SimTypeLong(signed=True, label=None), label=None),
        # long int llogbf (float X);
        "llogbf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeLong(signed=True, label=None), label=None),
        # long int llogbl (long double X);
        "llogbl": None,
        # long int llogbfN (_FloatN X);
        "llogbfN": None,
        # long int llogbfNx (_FloatNx X);
        "llogbfNx": None,
        # double pow (double BASE, double POWER);
        "pow": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float powf (float BASE, float POWER);
        "powf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double powl (long double BASE, long double POWER);
        "powl": None,
        # _FloatN powfN (_FloatN BASE, _FloatN POWER);
        "powfN": None,
        # _FloatNx powfNx (_FloatNx BASE, _FloatNx POWER);
        "powfNx": None,
        # double sqrt (double X);
        "sqrt": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float sqrtf (float X);
        "sqrtf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double sqrtl (long double X);
        "sqrtl": None,
        # _FloatN sqrtfN (_FloatN X);
        "sqrtfN": None,
        # _FloatNx sqrtfNx (_FloatNx X);
        "sqrtfNx": None,
        # double cbrt (double X);
        "cbrt": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float cbrtf (float X);
        "cbrtf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double cbrtl (long double X);
        "cbrtl": None,
        # _FloatN cbrtfN (_FloatN X);
        "cbrtfN": None,
        # _FloatNx cbrtfNx (_FloatNx X);
        "cbrtfNx": None,
        # double hypot (double X, double Y);
        "hypot": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float hypotf (float X, float Y);
        "hypotf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double hypotl (long double X, long double Y);
        "hypotl": None,
        # _FloatN hypotfN (_FloatN X, _FloatN Y);
        "hypotfN": None,
        # _FloatNx hypotfNx (_FloatNx X, _FloatNx Y);
        "hypotfNx": None,
        # double expm1 (double X);
        "expm1": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float expm1f (float X);
        "expm1f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double expm1l (long double X);
        "expm1l": None,
        # _FloatN expm1fN (_FloatN X);
        "expm1fN": None,
        # _FloatNx expm1fNx (_FloatNx X);
        "expm1fNx": None,
        # double log1p (double X);
        "log1p": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float log1pf (float X);
        "log1pf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double log1pl (long double X);
        "log1pl": None,
        # _FloatN log1pfN (_FloatN X);
        "log1pfN": None,
        # _FloatNx log1pfNx (_FloatNx X);
        "log1pfNx": None,
        # complex double cexp (complex double Z);
        "cexp": None,
        # complex float cexpf (complex float Z);
        "cexpf": None,
        # complex long double cexpl (complex long double Z);
        "cexpl": None,
        # complex _FloatN cexpfN (complex _FloatN Z);
        "cexpfN": None,
        # complex _FloatNx cexpfNx (complex _FloatNx Z);
        "cexpfNx": None,
        # complex double clog (complex double Z);
        "clog": None,
        # complex float clogf (complex float Z);
        "clogf": None,
        # complex long double clogl (complex long double Z);
        "clogl": None,
        # complex _FloatN clogfN (complex _FloatN Z);
        "clogfN": None,
        # complex _FloatNx clogfNx (complex _FloatNx Z);
        "clogfNx": None,
        # complex double clog10 (complex double Z);
        "clog10": None,
        # complex float clog10f (complex float Z);
        "clog10f": None,
        # complex long double clog10l (complex long double Z);
        "clog10l": None,
        # complex _FloatN clog10fN (complex _FloatN Z);
        "clog10fN": None,
        # complex _FloatNx clog10fNx (complex _FloatNx Z);
        "clog10fNx": None,
        # complex double csqrt (complex double Z);
        "csqrt": None,
        # complex float csqrtf (complex float Z);
        "csqrtf": None,
        # complex long double csqrtl (complex long double Z);
        "csqrtl": None,
        # complex _FloatN csqrtfN (_FloatN Z);
        "csqrtfN": None,
        # complex _FloatNx csqrtfNx (complex _FloatNx Z);
        "csqrtfNx": None,
        # complex double cpow (complex double BASE, complex double POWER);
        "cpow": None,
        # complex float cpowf (complex float BASE, complex float POWER);
        "cpowf": None,
        # complex long double cpowl (complex long double BASE, complex long double POWER);
        "cpowl": None,
        # complex _FloatN cpowfN (complex _FloatN BASE, complex _FloatN POWER);
        "cpowfN": None,
        # complex _FloatNx cpowfNx (complex _FloatNx BASE, complex _FloatNx POWER);
        "cpowfNx": None,
        # double sinh (double X);
        "sinh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float sinhf (float X);
        "sinhf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double sinhl (long double X);
        "sinhl": None,
        # _FloatN sinhfN (_FloatN X);
        "sinhfN": None,
        # _FloatNx sinhfNx (_FloatNx X);
        "sinhfNx": None,
        # double cosh (double X);
        "cosh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float coshf (float X);
        "coshf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double coshl (long double X);
        "coshl": None,
        # _FloatN coshfN (_FloatN X);
        "coshfN": None,
        # _FloatNx coshfNx (_FloatNx X);
        "coshfNx": None,
        # double tanh (double X);
        "tanh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float tanhf (float X);
        "tanhf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double tanhl (long double X);
        "tanhl": None,
        # _FloatN tanhfN (_FloatN X);
        "tanhfN": None,
        # _FloatNx tanhfNx (_FloatNx X);
        "tanhfNx": None,
        # complex double csinh (complex double Z);
        "csinh": None,
        # complex float csinhf (complex float Z);
        "csinhf": None,
        # complex long double csinhl (complex long double Z);
        "csinhl": None,
        # complex _FloatN csinhfN (complex _FloatN Z);
        "csinhfN": None,
        # complex _FloatNx csinhfNx (complex _FloatNx Z);
        "csinhfNx": None,
        # complex double ccosh (complex double Z);
        "ccosh": None,
        # complex float ccoshf (complex float Z);
        "ccoshf": None,
        # complex long double ccoshl (complex long double Z);
        "ccoshl": None,
        # complex _FloatN ccoshfN (complex _FloatN Z);
        "ccoshfN": None,
        # complex _FloatNx ccoshfNx (complex _FloatNx Z);
        "ccoshfNx": None,
        # complex double ctanh (complex double Z);
        "ctanh": None,
        # complex float ctanhf (complex float Z);
        "ctanhf": None,
        # complex long double ctanhl (complex long double Z);
        "ctanhl": None,
        # complex _FloatN ctanhfN (complex _FloatN Z);
        "ctanhfN": None,
        # complex _FloatNx ctanhfNx (complex _FloatNx Z);
        "ctanhfNx": None,
        # double asinh (double X);
        "asinh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float asinhf (float X);
        "asinhf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double asinhl (long double X);
        "asinhl": None,
        # _FloatN asinhfN (_FloatN X);
        "asinhfN": None,
        # _FloatNx asinhfNx (_FloatNx X);
        "asinhfNx": None,
        # double acosh (double X);
        "acosh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float acoshf (float X);
        "acoshf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double acoshl (long double X);
        "acoshl": None,
        # _FloatN acoshfN (_FloatN X);
        "acoshfN": None,
        # _FloatNx acoshfNx (_FloatNx X);
        "acoshfNx": None,
        # double atanh (double X);
        "atanh": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float atanhf (float X);
        "atanhf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double atanhl (long double X);
        "atanhl": None,
        # _FloatN atanhfN (_FloatN X);
        "atanhfN": None,
        # _FloatNx atanhfNx (_FloatNx X);
        "atanhfNx": None,
        # complex double casinh (complex double Z);
        "casinh": None,
        # complex float casinhf (complex float Z);
        "casinhf": None,
        # complex long double casinhl (complex long double Z);
        "casinhl": None,
        # complex _FloatN casinhfN (complex _FloatN Z);
        "casinhfN": None,
        # complex _FloatNx casinhfNx (complex _FloatNx Z);
        "casinhfNx": None,
        # complex double cacosh (complex double Z);
        "cacosh": None,
        # complex float cacoshf (complex float Z);
        "cacoshf": None,
        # complex long double cacoshl (complex long double Z);
        "cacoshl": None,
        # complex _FloatN cacoshfN (complex _FloatN Z);
        "cacoshfN": None,
        # complex _FloatNx cacoshfNx (complex _FloatNx Z);
        "cacoshfNx": None,
        # complex double catanh (complex double Z);
        "catanh": None,
        # complex float catanhf (complex float Z);
        "catanhf": None,
        # complex long double catanhl (complex long double Z);
        "catanhl": None,
        # complex _FloatN catanhfN (complex _FloatN Z);
        "catanhfN": None,
        # complex _FloatNx catanhfNx (complex _FloatNx Z);
        "catanhfNx": None,
        # double erf (double X);
        "erf": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float erff (float X);
        "erff": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double erfl (long double X);
        "erfl": None,
        # _FloatN erffN (_FloatN X);
        "erffN": None,
        # _FloatNx erffNx (_FloatNx X);
        "erffNx": None,
        # double erfc (double X);
        "erfc": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float erfcf (float X);
        "erfcf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double erfcl (long double X);
        "erfcl": None,
        # _FloatN erfcfN (_FloatN X);
        "erfcfN": None,
        # _FloatNx erfcfNx (_FloatNx X);
        "erfcfNx": None,
        # double lgamma (double X);
        "lgamma": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float lgammaf (float X);
        "lgammaf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double lgammal (long double X);
        "lgammal": None,
        # _FloatN lgammafN (_FloatN X);
        "lgammafN": None,
        # _FloatNx lgammafNx (_FloatNx X);
        "lgammafNx": None,
        # double lgamma_r (double X, int *SIGNP);
        "lgamma_r": SimTypeFunction([SimTypeDouble(), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeDouble(), label=None),
        # float lgammaf_r (float X, int *SIGNP);
        "lgammaf_r": SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double lgammal_r (long double X, int *SIGNP);
        "lgammal_r": None,
        # _FloatN lgammafN_r (_FloatN X, int *SIGNP);
        "lgammafN_r": None,
        # _FloatNx lgammafNx_r (_FloatNx X, int *SIGNP);
        "lgammafNx_r": None,
        # double gamma (double X);
        "gamma": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float gammaf (float X);
        "gammaf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double gammal (long double X);
        "gammal": None,
        # double tgamma (double X);
        "tgamma": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float tgammaf (float X);
        "tgammaf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double tgammal (long double X);
        "tgammal": None,
        # _FloatN tgammafN (_FloatN X);
        "tgammafN": None,
        # _FloatNx tgammafNx (_FloatNx X);
        "tgammafNx": None,
        # double j0 (double X);
        "j0": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float j0f (float X);
        "j0f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double j0l (long double X);
        "j0l": None,
        # _FloatN j0fN (_FloatN X);
        "j0fN": None,
        # _FloatNx j0fNx (_FloatNx X);
        "j0fNx": None,
        # double j1 (double X);
        "j1": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float j1f (float X);
        "j1f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double j1l (long double X);
        "j1l": None,
        # _FloatN j1fN (_FloatN X);
        "j1fN": None,
        # _FloatNx j1fNx (_FloatNx X);
        "j1fNx": None,
        # double jn (int N, double X);
        "jn": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeDouble()], SimTypeDouble(), label=None),
        # float jnf (int N, float X);
        "jnf": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double jnl (int N, long double X);
        "jnl": None,
        # _FloatN jnfN (int N, _FloatN X);
        "jnfN": None,
        # _FloatNx jnfNx (int N, _FloatNx X);
        "jnfNx": None,
        # double y0 (double X);
        "y0": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float y0f (float X);
        "y0f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double y0l (long double X);
        "y0l": None,
        # _FloatN y0fN (_FloatN X);
        "y0fN": None,
        # _FloatNx y0fNx (_FloatNx X);
        "y0fNx": None,
        # double y1 (double X);
        "y1": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float y1f (float X);
        "y1f": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double y1l (long double X);
        "y1l": None,
        # _FloatN y1fN (_FloatN X);
        "y1fN": None,
        # _FloatNx y1fNx (_FloatNx X);
        "y1fNx": None,
        # double yn (int N, double X);
        "yn": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeDouble()], SimTypeDouble(), label=None),
        # float ynf (int N, float X);
        "ynf": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double ynl (int N, long double X);
        "ynl": None,
        # _FloatN ynfN (int N, _FloatN X);
        "ynfN": None,
        # _FloatNx ynfNx (int N, _FloatNx X);
        "ynfNx": None,
        # int rand (void);
        "rand": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # void srand (unsigned int SEED);
        "srand": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeBottom(), label=None),
        # int rand_r (unsigned int *SEED);
        "rand_r": SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # long int random (void);
        "random": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # void srandom (unsigned int SEED);
        "srandom": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeBottom(), label=None),
        # char * initstate (unsigned int SEED, char *STATE, size_t SIZE);
        "initstate": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * setstate (char *STATE);
        "setstate": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int random_r (struct random_data *restrict BUF, int32_t *restrict RESULT);
        "random_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="random_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int srandom_r (unsigned int SEED, struct random_data *BUF);
        "srandom_r": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypePointer(SimStruct({}, name="random_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int initstate_r (unsigned int SEED, char *restrict STATEBUF, size_t STATELEN, struct random_data *restrict BUF);
        "initstate_r": SimTypeFunction([SimTypeInt(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimStruct({}, name="random_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setstate_r (char *restrict STATEBUF, struct random_data *restrict BUF);
        "setstate_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="random_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # double drand48 (void);
        "drand48": SimTypeFunction([ ], SimTypeDouble(), label=None),
        # double erand48 (unsigned short int XSUBI[3]);
        "erand48": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3)], SimTypeDouble(), label=None),
        # long int lrand48 (void);
        "lrand48": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # long int nrand48 (unsigned short int XSUBI[3]);
        "nrand48": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3)], SimTypeLong(signed=True, label=None), label=None),
        # long int mrand48 (void);
        "mrand48": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # long int jrand48 (unsigned short int XSUBI[3]);
        "jrand48": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3)], SimTypeLong(signed=True, label=None), label=None),
        # void srand48 (long int SEEDVAL);
        "srand48": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypeBottom(), label=None),
        # unsigned short int * seed48 (unsigned short int SEED16V[3]);
        "seed48": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3)], SimTypePointer(SimTypeShort(signed=False, label=None), label=None, offset=0), label=None),
        # void lcong48 (unsigned short int PARAM[7]);
        "lcong48": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 7)], SimTypeBottom(), label=None),
        # int drand48_r (struct drand48_data *BUFFER, double *RESULT);
        "drand48_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeDouble(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int erand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, double *RESULT);
        "erand48_r": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeDouble(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lrand48_r (struct drand48_data *BUFFER, long int *RESULT);
        "lrand48_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int nrand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, long int *RESULT);
        "nrand48_r": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int mrand48_r (struct drand48_data *BUFFER, long int *RESULT);
        "mrand48_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int jrand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, long int *RESULT);
        "jrand48_r": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0), SimTypePointer(SimTypeLong(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int srand48_r (long int SEEDVAL, struct drand48_data *BUFFER);
        "srand48_r": SimTypeFunction([SimTypeLong(signed=True, label=None), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int seed48_r (unsigned short int SEED16V[3], struct drand48_data *BUFFER);
        "seed48_r": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 3), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int lcong48_r (unsigned short int PARAM[7], struct drand48_data *BUFFER);
        "lcong48_r": SimTypeFunction([SimTypeFixedSizeArray(SimTypeShort(signed=False, label=None), 7), SimTypePointer(SimStruct({}, name="drand48_data", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # div_t div (int NUMERATOR, int DENOMINATOR);
        "div": None,
        # ldiv_t ldiv (long int NUMERATOR, long int DENOMINATOR);
        "ldiv": None,
        # lldiv_t lldiv (long long int NUMERATOR, long long int DENOMINATOR);
        "lldiv": None,
        # imaxdiv_t imaxdiv (intmax_t NUMERATOR, intmax_t DENOMINATOR);
        "imaxdiv": None,
        # int isinf (double X);
        "isinf": SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int isinff (float X);
        "isinff": SimTypeFunction([SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int isinfl (long double X);
        "isinfl": None,
        # int isnan (double X);
        "isnan": SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int isnanf (float X);
        "isnanf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int isnanl (long double X);
        "isnanl": None,
        # int finite (double X);
        "finite": SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int finitef (float X);
        "finitef": SimTypeFunction([SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int finitel (long double X);
        "finitel": None,
        # int feclearexcept (int EXCEPTS);
        "feclearexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int feraiseexcept (int EXCEPTS);
        "feraiseexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fesetexcept (int EXCEPTS);
        "fesetexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fetestexcept (int EXCEPTS);
        "fetestexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fegetexceptflag (fexcept_t *FLAGP, int EXCEPTS);
        "fegetexceptflag": None,
        # int fesetexceptflag (const fexcept_t *FLAGP, int EXCEPTS);
        "fesetexceptflag": None,
        # int fetestexceptflag (const fexcept_t *FLAGP, int EXCEPTS);
        "fetestexceptflag": None,
        # int fegetround (void);
        "fegetround": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int fesetround (int ROUND);
        "fesetround": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fegetenv (fenv_t *ENVP);
        "fegetenv": None,
        # int feholdexcept (fenv_t *ENVP);
        "feholdexcept": None,
        # int fesetenv (const fenv_t *ENVP);
        "fesetenv": None,
        # int feupdateenv (const fenv_t *ENVP);
        "feupdateenv": None,
        # int fegetmode (femode_t *MODEP);
        "fegetmode": None,
        # int fesetmode (const femode_t *MODEP);
        "fesetmode": None,
        # int feenableexcept (int EXCEPTS);
        "feenableexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fedisableexcept (int EXCEPTS);
        "fedisableexcept": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fegetexcept (void);
        "fegetexcept": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int abs (int NUMBER);
        "abs": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # long int labs (long int NUMBER);
        "labs": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # long long int llabs (long long int NUMBER);
        "llabs": SimTypeFunction([SimTypeLongLong(signed=True, label=None)], SimTypeLongLong(signed=True, label=None), label=None),
        # intmax_t imaxabs (intmax_t NUMBER);
        "imaxabs": None,
        # double fabs (double NUMBER);
        "fabs": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float fabsf (float NUMBER);
        "fabsf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fabsl (long double NUMBER);
        "fabsl": None,
        # _FloatN fabsfN (_FloatN NUMBER);
        "fabsfN": None,
        # _FloatNx fabsfNx (_FloatNx NUMBER);
        "fabsfNx": None,
        # double cabs (complex double Z);
        "cabs": None,
        # float cabsf (complex float Z);
        "cabsf": None,
        # long double cabsl (complex long double Z);
        "cabsl": None,
        # _FloatN cabsfN (complex _FloatN Z);
        "cabsfN": None,
        # _FloatNx cabsfNx (complex _FloatNx Z);
        "cabsfNx": None,
        # double frexp (double VALUE, int *EXPONENT);
        "frexp": SimTypeFunction([SimTypeDouble(), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeDouble(), label=None),
        # float frexpf (float VALUE, int *EXPONENT);
        "frexpf": SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double frexpl (long double VALUE, int *EXPONENT);
        "frexpl": None,
        # _FloatN frexpfN (_FloatN VALUE, int *EXPONENT);
        "frexpfN": None,
        # _FloatNx frexpfNx (_FloatNx VALUE, int *EXPONENT);
        "frexpfNx": None,
        # double ldexp (double VALUE, int EXPONENT);
        "ldexp": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None)], SimTypeDouble(), label=None),
        # float ldexpf (float VALUE, int EXPONENT);
        "ldexpf": SimTypeFunction([SimTypeFloat(size=32), SimTypeInt(signed=True, label=None)], SimTypeFloat(size=32), label=None),
        # long double ldexpl (long double VALUE, int EXPONENT);
        "ldexpl": None,
        # _FloatN ldexpfN (_FloatN VALUE, int EXPONENT);
        "ldexpfN": None,
        # _FloatNx ldexpfNx (_FloatNx VALUE, int EXPONENT);
        "ldexpfNx": None,
        # double scalb (double VALUE, double EXPONENT);
        "scalb": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float scalbf (float VALUE, float EXPONENT);
        "scalbf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double scalbl (long double VALUE, long double EXPONENT);
        "scalbl": None,
        # double scalbn (double X, int N);
        "scalbn": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None)], SimTypeDouble(), label=None),
        # float scalbnf (float X, int N);
        "scalbnf": SimTypeFunction([SimTypeFloat(size=32), SimTypeInt(signed=True, label=None)], SimTypeFloat(size=32), label=None),
        # long double scalbnl (long double X, int N);
        "scalbnl": None,
        # _FloatN scalbnfN (_FloatN X, int N);
        "scalbnfN": None,
        # _FloatNx scalbnfNx (_FloatNx X, int N);
        "scalbnfNx": None,
        # double scalbln (double X, long int N);
        "scalbln": SimTypeFunction([SimTypeDouble(), SimTypeLong(signed=True, label=None)], SimTypeDouble(), label=None),
        # float scalblnf (float X, long int N);
        "scalblnf": SimTypeFunction([SimTypeFloat(size=32), SimTypeLong(signed=True, label=None)], SimTypeFloat(size=32), label=None),
        # long double scalblnl (long double X, long int N);
        "scalblnl": None,
        # _FloatN scalblnfN (_FloatN X, long int N);
        "scalblnfN": None,
        # _FloatNx scalblnfNx (_FloatNx X, long int N);
        "scalblnfNx": None,
        # double significand (double X);
        "significand": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float significandf (float X);
        "significandf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double significandl (long double X);
        "significandl": None,
        # double ceil (double X);
        "ceil": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float ceilf (float X);
        "ceilf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double ceill (long double X);
        "ceill": None,
        # _FloatN ceilfN (_FloatN X);
        "ceilfN": None,
        # _FloatNx ceilfNx (_FloatNx X);
        "ceilfNx": None,
        # double floor (double X);
        "floor": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float floorf (float X);
        "floorf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double floorl (long double X);
        "floorl": None,
        # _FloatN floorfN (_FloatN X);
        "floorfN": None,
        # _FloatNx floorfNx (_FloatNx X);
        "floorfNx": None,
        # double trunc (double X);
        "trunc": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float truncf (float X);
        "truncf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double truncl (long double X);
        "truncl": None,
        # _FloatN truncfN (_FloatN X);
        "truncfN": None,
        # _FloatNx truncfNx (_FloatNx X);
        "truncfNx": None,
        # double rint (double X);
        "rint": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float rintf (float X);
        "rintf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double rintl (long double X);
        "rintl": None,
        # _FloatN rintfN (_FloatN X);
        "rintfN": None,
        # _FloatNx rintfNx (_FloatNx X);
        "rintfNx": None,
        # double nearbyint (double X);
        "nearbyint": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float nearbyintf (float X);
        "nearbyintf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double nearbyintl (long double X);
        "nearbyintl": None,
        # _FloatN nearbyintfN (_FloatN X);
        "nearbyintfN": None,
        # _FloatNx nearbyintfNx (_FloatNx X);
        "nearbyintfNx": None,
        # double round (double X);
        "round": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float roundf (float X);
        "roundf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double roundl (long double X);
        "roundl": None,
        # _FloatN roundfN (_FloatN X);
        "roundfN": None,
        # _FloatNx roundfNx (_FloatNx X);
        "roundfNx": None,
        # double roundeven (double X);
        "roundeven": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float roundevenf (float X);
        "roundevenf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double roundevenl (long double X);
        "roundevenl": None,
        # _FloatN roundevenfN (_FloatN X);
        "roundevenfN": None,
        # _FloatNx roundevenfNx (_FloatNx X);
        "roundevenfNx": None,
        # long int lrint (double X);
        "lrint": SimTypeFunction([SimTypeDouble()], SimTypeLong(signed=True, label=None), label=None),
        # long int lrintf (float X);
        "lrintf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeLong(signed=True, label=None), label=None),
        # long int lrintl (long double X);
        "lrintl": None,
        # long int lrintfN (_FloatN X);
        "lrintfN": None,
        # long int lrintfNx (_FloatNx X);
        "lrintfNx": None,
        # long long int llrint (double X);
        "llrint": SimTypeFunction([SimTypeDouble()], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int llrintf (float X);
        "llrintf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int llrintl (long double X);
        "llrintl": None,
        # long long int llrintfN (_FloatN X);
        "llrintfN": None,
        # long long int llrintfNx (_FloatNx X);
        "llrintfNx": None,
        # long int lround (double X);
        "lround": SimTypeFunction([SimTypeDouble()], SimTypeLong(signed=True, label=None), label=None),
        # long int lroundf (float X);
        "lroundf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeLong(signed=True, label=None), label=None),
        # long int lroundl (long double X);
        "lroundl": None,
        # long int lroundfN (_FloatN X);
        "lroundfN": None,
        # long int lroundfNx (_FloatNx X);
        "lroundfNx": None,
        # long long int llround (double X);
        "llround": SimTypeFunction([SimTypeDouble()], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int llroundf (float X);
        "llroundf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int llroundl (long double X);
        "llroundl": None,
        # long long int llroundfN (_FloatN X);
        "llroundfN": None,
        # long long int llroundfNx (_FloatNx X);
        "llroundfNx": None,
        # intmax_t fromfp (double X, int ROUND, unsigned int WIDTH);
        "fromfp": None,
        # intmax_t fromfpf (float X, int ROUND, unsigned int WIDTH);
        "fromfpf": None,
        # intmax_t fromfpl (long double X, int ROUND, unsigned int WIDTH);
        "fromfpl": None,
        # intmax_t fromfpfN (_FloatN X, int ROUND, unsigned int WIDTH);
        "fromfpfN": None,
        # intmax_t fromfpfNx (_FloatNx X, int ROUND, unsigned int WIDTH);
        "fromfpfNx": None,
        # uintmax_t ufromfp (double X, int ROUND, unsigned int WIDTH);
        "ufromfp": None,
        # uintmax_t ufromfpf (float X, int ROUND, unsigned int WIDTH);
        "ufromfpf": None,
        # uintmax_t ufromfpl (long double X, int ROUND, unsigned int WIDTH);
        "ufromfpl": None,
        # uintmax_t ufromfpfN (_FloatN X, int ROUND, unsigned int WIDTH);
        "ufromfpfN": None,
        # uintmax_t ufromfpfNx (_FloatNx X, int ROUND, unsigned int WIDTH);
        "ufromfpfNx": None,
        # intmax_t fromfpx (double X, int ROUND, unsigned int WIDTH);
        "fromfpx": None,
        # intmax_t fromfpxf (float X, int ROUND, unsigned int WIDTH);
        "fromfpxf": None,
        # intmax_t fromfpxl (long double X, int ROUND, unsigned int WIDTH);
        "fromfpxl": None,
        # intmax_t fromfpxfN (_FloatN X, int ROUND, unsigned int WIDTH);
        "fromfpxfN": None,
        # intmax_t fromfpxfNx (_FloatNx X, int ROUND, unsigned int WIDTH);
        "fromfpxfNx": None,
        # uintmax_t ufromfpx (double X, int ROUND, unsigned int WIDTH);
        "ufromfpx": None,
        # uintmax_t ufromfpxf (float X, int ROUND, unsigned int WIDTH);
        "ufromfpxf": None,
        # uintmax_t ufromfpxl (long double X, int ROUND, unsigned int WIDTH);
        "ufromfpxl": None,
        # uintmax_t ufromfpxfN (_FloatN X, int ROUND, unsigned int WIDTH);
        "ufromfpxfN": None,
        # uintmax_t ufromfpxfNx (_FloatNx X, int ROUND, unsigned int WIDTH);
        "ufromfpxfNx": None,
        # double modf (double VALUE, double *INTEGER-PART);
        "modf": None,
        # float modff (float VALUE, float *INTEGER-PART);
        "modff": None,
        # long double modfl (long double VALUE, long double *INTEGER-PART);
        "modfl": None,
        # _FloatN modffN (_FloatN VALUE, _FloatN *INTEGER-PART);
        "modffN": None,
        # _FloatNx modffNx (_FloatNx VALUE, _FloatNx *INTEGER-PART);
        "modffNx": None,
        # double fmod (double NUMERATOR, double DENOMINATOR);
        "fmod": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fmodf (float NUMERATOR, float DENOMINATOR);
        "fmodf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fmodl (long double NUMERATOR, long double DENOMINATOR);
        "fmodl": None,
        # _FloatN fmodfN (_FloatN NUMERATOR, _FloatN DENOMINATOR);
        "fmodfN": None,
        # _FloatNx fmodfNx (_FloatNx NUMERATOR, _FloatNx DENOMINATOR);
        "fmodfNx": None,
        # double remainder (double NUMERATOR, double DENOMINATOR);
        "remainder": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float remainderf (float NUMERATOR, float DENOMINATOR);
        "remainderf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double remainderl (long double NUMERATOR, long double DENOMINATOR);
        "remainderl": None,
        # _FloatN remainderfN (_FloatN NUMERATOR, _FloatN DENOMINATOR);
        "remainderfN": None,
        # _FloatNx remainderfNx (_FloatNx NUMERATOR, _FloatNx DENOMINATOR);
        "remainderfNx": None,
        # double drem (double NUMERATOR, double DENOMINATOR);
        "drem": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float dremf (float NUMERATOR, float DENOMINATOR);
        "dremf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double dreml (long double NUMERATOR, long double DENOMINATOR);
        "dreml": None,
        # double copysign (double X, double Y);
        "copysign": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float copysignf (float X, float Y);
        "copysignf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double copysignl (long double X, long double Y);
        "copysignl": None,
        # _FloatN copysignfN (_FloatN X, _FloatN Y);
        "copysignfN": None,
        # _FloatNx copysignfNx (_FloatNx X, _FloatNx Y);
        "copysignfNx": None,
        # int signbit (_float-type_ X);
        "signbit": None,
        # double nextafter (double X, double Y);
        "nextafter": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float nextafterf (float X, float Y);
        "nextafterf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double nextafterl (long double X, long double Y);
        "nextafterl": None,
        # _FloatN nextafterfN (_FloatN X, _FloatN Y);
        "nextafterfN": None,
        # _FloatNx nextafterfNx (_FloatNx X, _FloatNx Y);
        "nextafterfNx": None,
        # double nexttoward (double X, long double Y);
        "nexttoward": None,
        # float nexttowardf (float X, long double Y);
        "nexttowardf": None,
        # long double nexttowardl (long double X, long double Y);
        "nexttowardl": None,
        # double nextup (double X);
        "nextup": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float nextupf (float X);
        "nextupf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double nextupl (long double X);
        "nextupl": None,
        # _FloatN nextupfN (_FloatN X);
        "nextupfN": None,
        # _FloatNx nextupfNx (_FloatNx X);
        "nextupfNx": None,
        # double nextdown (double X);
        "nextdown": SimTypeFunction([SimTypeDouble()], SimTypeDouble(), label=None),
        # float nextdownf (float X);
        "nextdownf": SimTypeFunction([SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double nextdownl (long double X);
        "nextdownl": None,
        # _FloatN nextdownfN (_FloatN X);
        "nextdownfN": None,
        # _FloatNx nextdownfNx (_FloatNx X);
        "nextdownfNx": None,
        # double nan (const char *TAGP);
        "nan": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeDouble(), label=None),
        # float nanf (const char *TAGP);
        "nanf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double nanl (const char *TAGP);
        "nanl": None,
        # _FloatN nanfN (const char *TAGP);
        "nanfN": None,
        # _FloatNx nanfNx (const char *TAGP);
        "nanfNx": None,
        # int canonicalize (double *CX, const double *X);
        "canonicalize": SimTypeFunction([SimTypePointer(SimTypeDouble(), label=None, offset=0), SimTypePointer(SimTypeDouble(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int canonicalizef (float *CX, const float *X);
        "canonicalizef": SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), label=None, offset=0), SimTypePointer(SimTypeFloat(size=32), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int canonicalizel (long double *CX, const long double *X);
        "canonicalizel": None,
        # int canonicalizefN (_FloatN *CX, const _FloatN *X);
        "canonicalizefN": None,
        # int canonicalizefNx (_FloatNx *CX, const _FloatNx *X);
        "canonicalizefNx": None,
        # double getpayload (const double *X);
        "getpayload": SimTypeFunction([SimTypePointer(SimTypeDouble(), label=None, offset=0)], SimTypeDouble(), label=None),
        # float getpayloadf (const float *X);
        "getpayloadf": SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double getpayloadl (const long double *X);
        "getpayloadl": None,
        # _FloatN getpayloadfN (const _FloatN *X);
        "getpayloadfN": None,
        # _FloatNx getpayloadfNx (const _FloatNx *X);
        "getpayloadfNx": None,
        # int setpayload (double *X, double PAYLOAD);
        "setpayload": SimTypeFunction([SimTypePointer(SimTypeDouble(), label=None, offset=0), SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int setpayloadf (float *X, float PAYLOAD);
        "setpayloadf": SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), label=None, offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int setpayloadl (long double *X, long double PAYLOAD);
        "setpayloadl": None,
        # int setpayloadfN (_FloatN *X, _FloatN PAYLOAD);
        "setpayloadfN": None,
        # int setpayloadfNx (_FloatNx *X, _FloatNx PAYLOAD);
        "setpayloadfNx": None,
        # int setpayloadsig (double *X, double PAYLOAD);
        "setpayloadsig": SimTypeFunction([SimTypePointer(SimTypeDouble(), label=None, offset=0), SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int setpayloadsigf (float *X, float PAYLOAD);
        "setpayloadsigf": SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), label=None, offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int setpayloadsigl (long double *X, long double PAYLOAD);
        "setpayloadsigl": None,
        # int setpayloadsigfN (_FloatN *X, _FloatN PAYLOAD);
        "setpayloadsigfN": None,
        # int setpayloadsigfNx (_FloatNx *X, _FloatNx PAYLOAD);
        "setpayloadsigfNx": None,
        # int totalorder (double X, double Y);
        "totalorder": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int totalorderf (float X, float Y);
        "totalorderf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int totalorderl (long double X, long double Y);
        "totalorderl": None,
        # int totalorderfN (_FloatN X, _FloatN Y);
        "totalorderfN": None,
        # int totalorderfNx (_FloatNx X, _FloatNx Y);
        "totalorderfNx": None,
        # int totalordermag (double X, double Y);
        "totalordermag": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int totalordermagf (float X, float Y);
        "totalordermagf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int totalordermagl (long double X, long double Y);
        "totalordermagl": None,
        # int totalordermagfN (_FloatN X, _FloatN Y);
        "totalordermagfN": None,
        # int totalordermagfNx (_FloatNx X, _FloatNx Y);
        "totalordermagfNx": None,
        # double fmin (double X, double Y);
        "fmin": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fminf (float X, float Y);
        "fminf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fminl (long double X, long double Y);
        "fminl": None,
        # _FloatN fminfN (_FloatN X, _FloatN Y);
        "fminfN": None,
        # _FloatNx fminfNx (_FloatNx X, _FloatNx Y);
        "fminfNx": None,
        # double fmax (double X, double Y);
        "fmax": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fmaxf (float X, float Y);
        "fmaxf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fmaxl (long double X, long double Y);
        "fmaxl": None,
        # _FloatN fmaxfN (_FloatN X, _FloatN Y);
        "fmaxfN": None,
        # _FloatNx fmaxfNx (_FloatNx X, _FloatNx Y);
        "fmaxfNx": None,
        # double fminmag (double X, double Y);
        "fminmag": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fminmagf (float X, float Y);
        "fminmagf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fminmagl (long double X, long double Y);
        "fminmagl": None,
        # _FloatN fminmagfN (_FloatN X, _FloatN Y);
        "fminmagfN": None,
        # _FloatNx fminmagfNx (_FloatNx X, _FloatNx Y);
        "fminmagfNx": None,
        # double fmaxmag (double X, double Y);
        "fmaxmag": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fmaxmagf (float X, float Y);
        "fmaxmagf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fmaxmagl (long double X, long double Y);
        "fmaxmagl": None,
        # _FloatN fmaxmagfN (_FloatN X, _FloatN Y);
        "fmaxmagfN": None,
        # _FloatNx fmaxmagfNx (_FloatNx X, _FloatNx Y);
        "fmaxmagfNx": None,
        # double fdim (double X, double Y);
        "fdim": SimTypeFunction([SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fdimf (float X, float Y);
        "fdimf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fdiml (long double X, long double Y);
        "fdiml": None,
        # _FloatN fdimfN (_FloatN X, _FloatN Y);
        "fdimfN": None,
        # _FloatNx fdimfNx (_FloatNx X, _FloatNx Y);
        "fdimfNx": None,
        # double fma (double X, double Y, double Z);
        "fma": SimTypeFunction([SimTypeDouble(), SimTypeDouble(), SimTypeDouble()], SimTypeDouble(), label=None),
        # float fmaf (float X, float Y, float Z);
        "fmaf": SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeFloat(size=32), label=None),
        # long double fmal (long double X, long double Y, long double Z);
        "fmal": None,
        # _FloatN fmafN (_FloatN X, _FloatN Y, _FloatN Z);
        "fmafN": None,
        # _FloatNx fmafNx (_FloatNx X, _FloatNx Y, _FloatNx Z);
        "fmafNx": None,
        # double creal (complex double Z);
        "creal": None,
        # float crealf (complex float Z);
        "crealf": None,
        # long double creall (complex long double Z);
        "creall": None,
        # _FloatN crealfN (complex _FloatN Z);
        "crealfN": None,
        # _FloatNx crealfNx (complex _FloatNx Z);
        "crealfNx": None,
        # double cimag (complex double Z);
        "cimag": None,
        # float cimagf (complex float Z);
        "cimagf": None,
        # long double cimagl (complex long double Z);
        "cimagl": None,
        # _FloatN cimagfN (complex _FloatN Z);
        "cimagfN": None,
        # _FloatNx cimagfNx (complex _FloatNx Z);
        "cimagfNx": None,
        # complex double conj (complex double Z);
        "conj": None,
        # complex float conjf (complex float Z);
        "conjf": None,
        # complex long double conjl (complex long double Z);
        "conjl": None,
        # complex _FloatN conjfN (complex _FloatN Z);
        "conjfN": None,
        # complex _FloatNx conjfNx (complex _FloatNx Z);
        "conjfNx": None,
        # double carg (complex double Z);
        "carg": None,
        # float cargf (complex float Z);
        "cargf": None,
        # long double cargl (complex long double Z);
        "cargl": None,
        # _FloatN cargfN (complex _FloatN Z);
        "cargfN": None,
        # _FloatNx cargfNx (complex _FloatNx Z);
        "cargfNx": None,
        # complex double cproj (complex double Z);
        "cproj": None,
        # complex float cprojf (complex float Z);
        "cprojf": None,
        # complex long double cprojl (complex long double Z);
        "cprojl": None,
        # complex _FloatN cprojfN (complex _FloatN Z);
        "cprojfN": None,
        # complex _FloatNx cprojfNx (complex _FloatNx Z);
        "cprojfNx": None,
        # long int strtol (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtol": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # long int wcstol (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstol": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # unsigned long int strtoul (const char *retrict STRING, char **restrict TAILPTR, int BASE);
        "strtoul": None,
        # unsigned long int wcstoul (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoul": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # long long int strtoll (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtoll": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int wcstoll (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoll": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int strtoq (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtoq": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=True, label=None), label=None),
        # long long int wcstoq (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoq": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=True, label=None), label=None),
        # unsigned long long int strtoull (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtoull": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=False, label=None), label=None),
        # unsigned long long int wcstoull (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoull": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=False, label=None), label=None),
        # unsigned long long int strtouq (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtouq": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=False, label=None), label=None),
        # unsigned long long int wcstouq (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstouq": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLongLong(signed=False, label=None), label=None),
        # intmax_t strtoimax (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtoimax": None,
        # intmax_t wcstoimax (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoimax": None,
        # uintmax_t strtoumax (const char *restrict STRING, char **restrict TAILPTR, int BASE);
        "strtoumax": None,
        # uintmax_t wcstoumax (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);
        "wcstoumax": None,
        # long int atol (const char *STRING);
        "atol": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLong(signed=True, label=None), label=None),
        # int atoi (const char *STRING);
        "atoi": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # long long int atoll (const char *STRING);
        "atoll": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeLongLong(signed=True, label=None), label=None),
        # double strtod (const char *restrict STRING, char **restrict TAILPTR);
        "strtod": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeDouble(), label=None),
        # float strtof (const char *STRING, char **TAILPTR);
        "strtof": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double strtold (const char *STRING, char **TAILPTR);
        "strtold": None,
        # _FloatN strtofN (const char *STRING, char **TAILPTR);
        "strtofN": None,
        # _FloatNx strtofNx (const char *STRING, char **TAILPTR);
        "strtofNx": None,
        # double wcstod (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR);
        "wcstod": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0)], SimTypeDouble(), label=None),
        # float wcstof (const wchar_t *STRING, wchar_t **TAILPTR);
        "wcstof": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), label=None, offset=0)], SimTypeFloat(size=32), label=None),
        # long double wcstold (const wchar_t *STRING, wchar_t **TAILPTR);
        "wcstold": None,
        # _FloatN wcstofN (const wchar_t *STRING, wchar_t **TAILPTR);
        "wcstofN": None,
        # _FloatNx wcstofNx (const wchar_t *STRING, wchar_t **TAILPTR);
        "wcstofNx": None,
        # double atof (const char *STRING);
        "atof": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeDouble(), label=None),
        # int strfromd (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, double VALUE);
        "strfromd": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeDouble()], SimTypeInt(signed=True, label=None), label=None),
        # int strfromf (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, float VALUE);
        "strfromf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFloat(size=32)], SimTypeInt(signed=True, label=None), label=None),
        # int strfroml (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, long double VALUE);
        "strfroml": None,
        # int strfromfN (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, _FloatN VALUE);
        "strfromfN": None,
        # int strfromfNx (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, _FloatNx VALUE);
        "strfromfNx": None,
        # char * ecvt (double VALUE, int NDIGIT, int *DECPT, int *NEG);
        "ecvt": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * fcvt (double VALUE, int NDIGIT, int *DECPT, int *NEG);
        "fcvt": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * gcvt (double VALUE, int NDIGIT, char *BUF);
        "gcvt": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * qecvt (long double VALUE, int NDIGIT, int *DECPT, int *NEG);
        "qecvt": None,
        # char * qfcvt (long double VALUE, int NDIGIT, int *DECPT, int *NEG);
        "qfcvt": None,
        # char * qgcvt (long double VALUE, int NDIGIT, char *BUF);
        "qgcvt": None,
        # int ecvt_r (double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);
        "ecvt_r": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int fcvt_r (double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);
        "fcvt_r": SimTypeFunction([SimTypeDouble(), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int qecvt_r (long double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);
        "qecvt_r": None,
        # int qfcvt_r (long double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);
        "qfcvt_r": None,
        # double difftime (time_t TIME1, time_t TIME0);
        "difftime": None,
        # clock_t clock (void);
        "clock": None,
        # clock_t times (struct tms *BUFFER);
        "times": None,
        # time_t time (time_t *RESULT);
        "time": None,
        # int stime (const time_t *NEWTIME);
        "stime": None,
        # int gettimeofday (struct timeval *TP, struct timezone *TZP);
        "gettimeofday": SimTypeFunction([SimTypePointer(SimStruct({}, name="timeval", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="timezone", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int settimeofday (const struct timeval *TP, const struct timezone *TZP);
        "settimeofday": SimTypeFunction([SimTypePointer(SimStruct({}, name="timeval", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="timezone", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int adjtime (const struct timeval *DELTA, struct timeval *OLDDELTA);
        "adjtime": SimTypeFunction([SimTypePointer(SimStruct({}, name="timeval", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="timeval", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int adjtimex (struct timex *TIMEX);
        "adjtimex": SimTypeFunction([SimTypePointer(SimStruct({}, name="timex", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # struct tm * localtime (const time_t *TIME);
        "localtime": None,
        # struct tm * localtime_r (const time_t *TIME, struct tm *RESULTP);
        "localtime_r": None,
        # struct tm * gmtime (const time_t *TIME);
        "gmtime": None,
        # struct tm * gmtime_r (const time_t *TIME, struct tm *RESULTP);
        "gmtime_r": None,
        # time_t mktime (struct tm *BROKENTIME);
        "mktime": None,
        # time_t timelocal (struct tm *BROKENTIME);
        "timelocal": None,
        # time_t timegm (struct tm *BROKENTIME);
        "timegm": None,
        # int ntp_gettime (struct ntptimeval *TPTR);
        "ntp_gettime": SimTypeFunction([SimTypePointer(SimStruct({}, name="ntptimeval", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int ntp_adjtime (struct timex *TPTR);
        "ntp_adjtime": SimTypeFunction([SimTypePointer(SimStruct({}, name="timex", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # char * asctime (const struct tm *BROKENTIME);
        "asctime": SimTypeFunction([SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * asctime_r (const struct tm *BROKENTIME, char *BUFFER);
        "asctime_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * ctime (const time_t *TIME);
        "ctime": None,
        # char * ctime_r (const time_t *TIME, char *BUFFER);
        "ctime_r": None,
        # size_t strftime (char *S, size_t SIZE, const char *TEMPLATE, const struct tm *BROKENTIME);
        "strftime": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # size_t wcsftime (wchar_t *S, size_t SIZE, const wchar_t *TEMPLATE, const struct tm *BROKENTIME);
        "wcsftime": SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeShort(signed=True, label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0)], SimTypeLong(signed=False, label=None), label=None),
        # char * strptime (const char *S, const char *FMT, struct tm *TP);
        "strptime": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # struct tm * getdate (const char *STRING);
        "getdate": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0), label=None),
        # int getdate_r (const char *STRING, struct tm *TP);
        "getdate_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="tm", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void tzset (void);
        "tzset": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int setitimer (int WHICH, const struct itimerval *NEW, struct itimerval *OLD);
        "setitimer": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="itimerval", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="itimerval", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getitimer (int WHICH, struct itimerval *OLD);
        "getitimer": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="itimerval", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # unsigned int alarm (unsigned int SECONDS);
        "alarm": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # unsigned int sleep (unsigned int SECONDS);
        "sleep": SimTypeFunction([SimTypeInt(signed=False, label=None)], SimTypeInt(signed=False, label=None), label=None),
        # int nanosleep (const struct timespec *REQUESTED_TIME, struct timespec *REMAINING);
        "nanosleep": SimTypeFunction([SimTypePointer(SimStruct({}, name="timespec", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="timespec", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getrusage (int PROCESSES, struct rusage *RUSAGE);
        "getrusage": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="rusage", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int vtimes (struct vtimes *CURRENT, struct vtimes *CHILD);
        "vtimes": SimTypeFunction([SimTypePointer(SimStruct({}, name="vtimes", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="vtimes", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getrlimit (int RESOURCE, struct rlimit *RLP);
        "getrlimit": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="rlimit", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getrlimit64 (int RESOURCE, struct rlimit64 *RLP);
        "getrlimit64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="rlimit64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setrlimit (int RESOURCE, const struct rlimit *RLP);
        "setrlimit": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="rlimit", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setrlimit64 (int RESOURCE, const struct rlimit64 *RLP);
        "setrlimit64": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="rlimit64", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # long int ulimit (int CMD, ...);
        "ulimit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # int vlimit (int RESOURCE, int LIMIT);
        "vlimit": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sched_setscheduler (pid_t PID, int POLICY, const struct sched_param *PARAM);
        "sched_setscheduler": None,
        # int sched_getscheduler (pid_t PID);
        "sched_getscheduler": None,
        # int sched_setparam (pid_t PID, const struct sched_param *PARAM);
        "sched_setparam": None,
        # int sched_getparam (pid_t PID, struct sched_param *PARAM);
        "sched_getparam": None,
        # int sched_get_priority_min (int POLICY);
        "sched_get_priority_min": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sched_get_priority_max (int POLICY);
        "sched_get_priority_max": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sched_rr_get_interval (pid_t PID, struct timespec *INTERVAL);
        "sched_rr_get_interval": None,
        # int sched_yield (void);
        "sched_yield": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int getpriority (int CLASS, int ID);
        "getpriority": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setpriority (int CLASS, int ID, int NICEVAL);
        "setpriority": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int nice (int INCREMENT);
        "nice": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sched_getaffinity (pid_t PID, size_t CPUSETSIZE, cpu_set_t *CPUSET);
        "sched_getaffinity": None,
        # int sched_setaffinity (pid_t PID, size_t CPUSETSIZE, const cpu_set_t *CPUSET);
        "sched_setaffinity": None,
        # int getpagesize (void);
        "getpagesize": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # long int get_phys_pages (void);
        "get_phys_pages": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # long int get_avphys_pages (void);
        "get_avphys_pages": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # int get_nprocs_conf (void);
        "get_nprocs_conf": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int get_nprocs (void);
        "get_nprocs": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int getloadavg (double LOADAVG[], int NELEM);
        "getloadavg": SimTypeFunction([SimTypeFixedSizeArray(SimTypeDouble(), 0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void longjmp (jmp_buf STATE, int VALUE);
        "longjmp": None,
        # int sigsetjmp (sigjmp_buf STATE, int SAVESIGS);
        "sigsetjmp": None,
        # void siglongjmp (sigjmp_buf STATE, int VALUE);
        "siglongjmp": None,
        # int getcontext (ucontext_t *UCP);
        "getcontext": None,
        # void makecontext (ucontext_t *UCP, void (*FUNC);
        "makecontext": None,
        # int setcontext (const ucontext_t *UCP);
        "setcontext": None,
        # int swapcontext (ucontext_t *restrict OUCP, const ucontext_t *restrict UCP);
        "swapcontext": None,
        # char * strsignal (int SIGNUM);
        "strsignal": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void psignal (int SIGNUM, const char *MESSAGE);
        "psignal": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # sighandler_t signal (int SIGNUM, sighandler_t ACTION);
        "signal": None,
        # sighandler_t sysv_signal (int SIGNUM, sighandler_t ACTION);
        "sysv_signal": None,
        # sighandler_t ssignal (int SIGNUM, sighandler_t ACTION);
        "ssignal": None,
        # int sigaction (int SIGNUM, const struct sigaction *restrict ACTION, struct sigaction *restrict OLD-ACTION);
        "sigaction": None,
        # int raise (int SIGNUM);
        "raise": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int gsignal (int SIGNUM);
        "gsignal": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int kill (pid_t PID, int SIGNUM);
        "kill": None,
        # int killpg (int PGID, int SIGNUM);
        "killpg": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sigemptyset (sigset_t *SET);
        "sigemptyset": None,
        # int sigfillset (sigset_t *SET);
        "sigfillset": None,
        # int sigaddset (sigset_t *SET, int SIGNUM);
        "sigaddset": None,
        # int sigdelset (sigset_t *SET, int SIGNUM);
        "sigdelset": None,
        # int sigismember (const sigset_t *SET, int SIGNUM);
        "sigismember": None,
        # int sigprocmask (int HOW, const sigset_t *restrict SET, sigset_t *restrict OLDSET);
        "sigprocmask": None,
        # int sigpending (sigset_t *SET);
        "sigpending": None,
        # int pause (void);
        "pause": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # int sigsuspend (const sigset_t *SET);
        "sigsuspend": None,
        # int sigaltstack (const stack_t *restrict STACK, stack_t *restrict OLDSTACK);
        "sigaltstack": None,
        # int sigstack (struct sigstack *STACK, struct sigstack *OLDSTACK);
        "sigstack": SimTypeFunction([SimTypePointer(SimStruct({}, name="sigstack", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="sigstack", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int siginterrupt (int SIGNUM, int FAILFLAG);
        "siginterrupt": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sigblock (int MASK);
        "sigblock": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sigsetmask (int MASK);
        "sigsetmask": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sigpause (int MASK);
        "sigpause": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int getopt (int ARGC, char *const *ARGV, const char *OPTIONS);
        "getopt": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getopt_long (int ARGC, char *const *ARGV, const char *SHORTOPTS, const struct option *LONGOPTS, int *INDEXPTR);
        "getopt_long": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="option", pack=True), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getopt_long_only (int ARGC, char *const *ARGV, const char *SHORTOPTS, const struct option *LONGOPTS, int *INDEXPTR);
        "getopt_long_only": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="option", pack=True), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # error_t argp_parse (const struct argp *ARGP, int ARGC, char **ARGV, unsigned FLAGS, int *ARG_INDEX, void *INPUT);
        "argp_parse": None,
        # void argp_usage (const struct argp_state *STATE);
        "argp_usage": SimTypeFunction([SimTypePointer(SimStruct({}, name="argp_state", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # void argp_error (const struct argp_state *STATE, const char *FMT, ...);
        "argp_error": SimTypeFunction([SimTypePointer(SimStruct({}, name="argp_state", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void argp_failure (const struct argp_state *STATE, int STATUS, int ERRNUM, const char *FMT, ...);
        "argp_failure": SimTypeFunction([SimTypePointer(SimStruct({}, name="argp_state", pack=True), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void argp_state_help (const struct argp_state *STATE, FILE *STREAM, unsigned FLAGS);
        "argp_state_help": None,
        # void argp_help (const struct argp *ARGP, FILE *STREAM, unsigned FLAGS, char *NAME);
        "argp_help": None,
        # int getsubopt (char **OPTIONP, char *const *TOKENS, char **VALUEP);
        "getsubopt": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # char * getenv (const char *NAME);
        "getenv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * secure_getenv (const char *NAME);
        "secure_getenv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int putenv (char *STRING);
        "putenv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setenv (const char *NAME, const char *VALUE, int REPLACE);
        "setenv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int unsetenv (const char *NAME);
        "unsetenv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int clearenv (void);
        "clearenv": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # unsigned long int getauxval (unsigned long int TYPE);
        "getauxval": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # long int syscall (long int SYSNO, ...);
        "syscall": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # void exit (int STATUS);
        "exit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # int atexit (void (*FUNCTION);
        "atexit": None,
        # int on_exit (void (*FUNCTION);
        "on_exit": None,
        # void abort (void);
        "abort": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void _exit (int STATUS);
        "_exit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void _Exit (int STATUS);
        "_Exit": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # int system (const char *COMMAND);
        "system": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # pid_t getpid (void);
        "getpid": None,
        # pid_t getppid (void);
        "getppid": None,
        # pid_t fork (void);
        "fork": None,
        # pid_t vfork (void);
        "vfork": None,
        # int execv (const char *FILENAME, char *const ARGV[]);
        "execv": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFixedSizeArray(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), 0)], SimTypeInt(signed=True, label=None), label=None),
        # int execl (const char *FILENAME, const char *ARG0, ...);
        "execl": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int execve (const char *FILENAME, char *const ARGV[], char *const ENV[]);
        "execve": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFixedSizeArray(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), 0), SimTypeFixedSizeArray(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), 0)], SimTypeInt(signed=True, label=None), label=None),
        # int execle (const char *FILENAME, const char *ARG0, ..., char *const ENV[]);
        "execle": None,
        # int execvp (const char *FILENAME, char *const ARGV[]);
        "execvp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeFixedSizeArray(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), 0)], SimTypeInt(signed=True, label=None), label=None),
        # int execlp (const char *FILENAME, const char *ARG0, ...);
        "execlp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # pid_t waitpid (pid_t PID, int *STATUS_PTR, int OPTIONS);
        "waitpid": None,
        # pid_t wait (int *STATUS_PTR);
        "wait": None,
        # pid_t wait4 (pid_t PID, int *STATUS_PTR, int OPTIONS, struct rusage *USAGE);
        "wait4": None,
        # pid_t wait3 (int *STATUS_PTR, int OPTIONS, struct rusage *USAGE);
        "wait3": None,
        # int semctl (int SEMID, int SEMNUM, int CMD);
        "semctl": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int semget (key_t KEY, int NSEMS, int SEMFLG);
        "semget": None,
        # int semop (int SEMID, struct sembuf *SOPS, size_t NSOPS);
        "semop": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sembuf", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int semtimedop (int SEMID, struct sembuf *SOPS, size_t NSOPS, const struct timespec *TIMEOUT);
        "semtimedop": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="sembuf", pack=True), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimStruct({}, name="timespec", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int sem_init (sem_t *SEM, int PSHARED, unsigned int VALUE);
        "sem_init": None,
        # int sem_destroy (sem_t *SEM);
        "sem_destroy": None,
        # sem_t *sem_open (const char *NAME, int OFLAG, ...);
        "*sem_open": None,
        # int sem_close (sem_t *SEM);
        "sem_close": None,
        # int sem_unlink (const char *NAME);
        "sem_unlink": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int sem_wait (sem_t *SEM);
        "sem_wait": None,
        # int sem_timedwait (sem_t *SEM, const struct timespec *ABSTIME);
        "sem_timedwait": None,
        # int sem_trywait (sem_t *SEM);
        "sem_trywait": None,
        # int sem_post (sem_t *SEM);
        "sem_post": None,
        # int sem_getvalue (sem_t *SEM, int *SVAL);
        "sem_getvalue": None,
        # char * ctermid (char *STRING);
        "ctermid": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # pid_t setsid (void);
        "setsid": None,
        # pid_t getsid (pid_t PID);
        "getsid": None,
        # pid_t getpgrp (void);
        "getpgrp": None,
        # int getpgid (pid_t PID);
        "getpgid": None,
        # int setpgid (pid_t PID, pid_t PGID);
        "setpgid": None,
        # int setpgrp (pid_t PID, pid_t PGID);
        "setpgrp": None,
        # pid_t tcgetpgrp (int FILEDES);
        "tcgetpgrp": None,
        # int tcsetpgrp (int FILEDES, pid_t PGID);
        "tcsetpgrp": None,
        # pid_t tcgetsid (int FILDES);
        "tcgetsid": None,
        # uid_t getuid (void);
        "getuid": SimTypeFunction([ ], SimTypeLong(signed=False, label=None), label=None),
        # gid_t getgid (void);
        "getgid": SimTypeFunction([ ], SimTypeLong(signed=False, label=None), label=None),
        # uid_t geteuid (void);
        "geteuid": SimTypeFunction([ ], SimTypeLong(signed=False, label=None), label=None),
        # gid_t getegid (void);
        "getegid": SimTypeFunction([ ], SimTypeLong(signed=False, label=None), label=None),
        # int getgroups (int COUNT, gid_t *GROUPS);
        "getgroups": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int seteuid (uid_t NEWEUID);
        "seteuid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setuid (uid_t NEWUID);
        "setuid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setreuid (uid_t RUID, uid_t EUID);
        "setreuid": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setegid (gid_t NEWGID);
        "setegid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setgid (gid_t NEWGID);
        "setgid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setregid (gid_t RGID, gid_t EGID);
        "setregid": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setgroups (size_t COUNT, const gid_t *GROUPS);
        "setgroups": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int initgroups (const char *USER, gid_t GROUP);
        "initgroups": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int getgrouplist (const char *USER, gid_t GROUP, gid_t *GROUPS, int *NGROUPS);
        "getgrouplist": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0), SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # char * getlogin (void);
        "getlogin": SimTypeFunction([ ], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * cuserid (char *STRING);
        "cuserid": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void setutent (void);
        "setutent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct utmp * getutent (void);
        "getutent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None),
        # void endutent (void);
        "endutent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct utmp * getutid (const struct utmp *ID);
        "getutid": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None),
        # struct utmp * getutline (const struct utmp *LINE);
        "getutline": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None),
        # struct utmp * pututline (const struct utmp *UTMP);
        "pututline": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None),
        # int getutent_r (struct utmp *BUFFER, struct utmp **RESULT);
        "getutent_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getutid_r (const struct utmp *ID, struct utmp *BUFFER, struct utmp **RESULT);
        "getutid_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getutline_r (const struct utmp *LINE, struct utmp *BUFFER, struct utmp **RESULT);
        "getutline_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int utmpname (const char *FILE);
        "utmpname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void updwtmp (const char *WTMP_FILE, const struct utmp *UTMP);
        "updwtmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # void setutxent (void);
        "setutxent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct utmpx * getutxent (void);
        "getutxent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0), label=None),
        # void endutxent (void);
        "endutxent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct utmpx * getutxid (const struct utmpx *ID);
        "getutxid": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0), label=None),
        # struct utmpx * getutxline (const struct utmpx *LINE);
        "getutxline": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0), label=None),
        # struct utmpx * pututxline (const struct utmpx *UTMP);
        "pututxline": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0)], SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0), label=None),
        # int utmpxname (const char *FILE);
        "utmpxname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getutmp (const struct utmpx *UTMPX, struct utmp *UTMP);
        "getutmp": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getutmpx (const struct utmp *UTMP, struct utmpx *UTMPX);
        "getutmpx": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0), SimTypePointer(SimStruct({}, name="utmpx", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int login_tty (int FILEDES);
        "login_tty": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void login (const struct utmp *ENTRY);
        "login": SimTypeFunction([SimTypePointer(SimStruct({}, name="utmp", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int logout (const char *UT_LINE);
        "logout": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void logwtmp (const char *UT_LINE, const char *UT_NAME, const char *UT_HOST);
        "logwtmp": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # struct passwd * getpwuid (uid_t UID);
        "getpwuid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None),
        # int getpwuid_r (uid_t UID, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);
        "getpwuid_r": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # struct passwd * getpwnam (const char *NAME);
        "getpwnam": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None),
        # int getpwnam_r (const char *NAME, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);
        "getpwnam_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # struct passwd * fgetpwent (FILE *STREAM);
        "fgetpwent": None,
        # int fgetpwent_r (FILE *STREAM, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);
        "fgetpwent_r": None,
        # void setpwent (void);
        "setpwent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct passwd * getpwent (void);
        "getpwent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None),
        # int getpwent_r (struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);
        "getpwent_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="passwd", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void endpwent (void);
        "endpwent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int putpwent (const struct passwd *P, FILE *STREAM);
        "putpwent": None,
        # struct group * getgrgid (gid_t GID);
        "getgrgid": SimTypeFunction([SimTypeLong(signed=False, label=None)], SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None),
        # int getgrgid_r (gid_t GID, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);
        "getgrgid_r": SimTypeFunction([SimTypeLong(signed=False, label=None), SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # struct group * getgrnam (const char *NAME);
        "getgrnam": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None),
        # int getgrnam_r (const char *NAME, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);
        "getgrnam_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # struct group * fgetgrent (FILE *STREAM);
        "fgetgrent": None,
        # int fgetgrent_r (FILE *STREAM, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);
        "fgetgrent_r": None,
        # void setgrent (void);
        "setgrent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct group * getgrent (void);
        "getgrent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None),
        # int getgrent_r (struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);
        "getgrent_r": SimTypeFunction([SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypePointer(SimStruct({}, name="group", pack=True), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void endgrent (void);
        "endgrent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int setnetgrent (const char *NETGROUP);
        "setnetgrent": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getnetgrent (char **HOSTP, char **USERP, char **DOMAINP);
        "getnetgrent": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int getnetgrent_r (char **HOSTP, char **USERP, char **DOMAINP, char *BUFFER, size_t BUFLEN);
        "getnetgrent_r": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # void endnetgrent (void);
        "endnetgrent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # int innetgr (const char *NETGROUP, const char *HOST, const char *USER, const char *DOMAIN);
        "innetgr": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int gethostname (char *NAME, size_t SIZE);
        "gethostname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int sethostname (const char *NAME, size_t LENGTH);
        "sethostname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int getdomainnname (char *NAME, size_t LENGTH);
        "getdomainnname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int setdomainname (const char *NAME, size_t LENGTH);
        "setdomainname": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # long int gethostid (void);
        "gethostid": SimTypeFunction([ ], SimTypeLong(signed=True, label=None), label=None),
        # int sethostid (long int ID);
        "sethostid": SimTypeFunction([SimTypeLong(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int uname (struct utsname *INFO);
        "uname": SimTypeFunction([SimTypePointer(SimStruct({}, name="utsname", pack=True), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int setfsent (void);
        "setfsent": SimTypeFunction([ ], SimTypeInt(signed=True, label=None), label=None),
        # void endfsent (void);
        "endfsent": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # struct fstab * getfsent (void);
        "getfsent": SimTypeFunction([ ], SimTypePointer(SimStruct({}, name="fstab", pack=True), label=None, offset=0), label=None),
        # struct fstab * getfsspec (const char *NAME);
        "getfsspec": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="fstab", pack=True), label=None, offset=0), label=None),
        # struct fstab * getfsfile (const char *NAME);
        "getfsfile": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimStruct({}, name="fstab", pack=True), label=None, offset=0), label=None),
        # FILE * setmntent (const char *FILE, const char *MODE);
        "setmntent": None,
        # int endmntent (FILE *STREAM);
        "endmntent": None,
        # struct mntent * getmntent (FILE *STREAM);
        "getmntent": None,
        # struct mntent * getmntent_r (FILE *STREAM, struct mntent *RESULT, char *BUFFER, int BUFSIZE);
        "getmntent_r": None,
        # int addmntent (FILE *STREAM, const struct mntent *MNT);
        "addmntent": None,
        # char * hasmntopt (const struct mntent *MNT, const char *OPT);
        "hasmntopt": SimTypeFunction([SimTypePointer(SimStruct({}, name="mntent", pack=True), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # int mount (const char *SPECIAL_FILE, const char *DIR, const char *FSTYPE, unsigned long int OPTIONS, const void *DATA);
        "mount": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int umount2 (const char *FILE, int FLAGS);
        "umount2": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int umount (const char *FILE);
        "umount": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # int sysctl (int *NAMES, int NLEN, void *OLDVAL, size_t *OLDLENP, void *NEWVAL, size_t NEWLEN);
        "sysctl": SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypePointer(SimTypeLong(signed=False, label=None), label=None, offset=0), SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # long int sysconf (int PARAMETER);
        "sysconf": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # long int pathconf (const char *FILENAME, int PARAMETER);
        "pathconf": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # long int fpathconf (int FILEDES, int PARAMETER);
        "fpathconf": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # size_t confstr (int PARAMETER, char *BUF, size_t LEN);
        "confstr": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeLong(signed=False, label=None), label=None),
        # char * getpass (const char *PROMPT);
        "getpass": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * crypt (const char *KEY, const char *SALT);
        "crypt": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # char * crypt_r (const char *KEY, const char *SALT, struct crypt_data * DATA);
        "crypt_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="crypt_data", pack=True), label=None, offset=0)], SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None),
        # void setkey (const char *KEY);
        "setkey": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # void encrypt (char *BLOCK, int EDFLAG);
        "encrypt": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # void setkey_r (const char *KEY, struct crypt_data * DATA);
        "setkey_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimStruct({}, name="crypt_data", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # void encrypt_r (char *BLOCK, int EDFLAG, struct crypt_data * DATA);
        "encrypt_r": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypePointer(SimStruct({}, name="crypt_data", pack=True), label=None, offset=0)], SimTypeBottom(), label=None),
        # int ecb_crypt (char *KEY, char *BLOCKS, unsigned int LEN, unsigned int MODE);
        "ecb_crypt": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None), SimTypeInt(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int DES_FAILED (int ERR);
        "DES_FAILED": SimTypeFunction([SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # int cbc_crypt (char *KEY, char *BLOCKS, unsigned int LEN, unsigned int MODE, char *IVEC);
        "cbc_crypt": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypePointer(SimTypeChar(label=None), label=None, offset=0), SimTypeInt(signed=False, label=None), SimTypeInt(signed=False, label=None), SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),
        # void des_setparity (char *KEY);
        "des_setparity": SimTypeFunction([SimTypePointer(SimTypeChar(label=None), label=None, offset=0)], SimTypeBottom(), label=None),
        # int getentropy (void *BUFFER, size_t LENGTH);
        "getentropy": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # ssize_t getrandom (void *BUFFER, size_t LENGTH, unsigned int FLAGS);
        "getrandom": SimTypeFunction([SimTypePointer(SimTypeBottom(), label=None, offset=0), SimTypeLong(signed=False, label=None), SimTypeInt(signed=False, label=None)], SimTypeLong(signed=True, label=None), label=None),
        # int backtrace (void **BUFFER, int SIZE);
        "backtrace": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypeInt(signed=True, label=None), label=None),
        # char ** backtrace_symbols (void *const *BUFFER, int SIZE);
        "backtrace_symbols": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None)], SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0), label=None),
        # void backtrace_symbols_fd (void *const *BUFFER, int SIZE, int FD);
        "backtrace_symbols_fd": SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(), label=None, offset=0), label=None, offset=0), SimTypeInt(signed=True, label=None), SimTypeInt(signed=True, label=None)], SimTypeBottom(), label=None),
        # int pthread_key_create (pthread_key_t *KEY, void (*DESTRUCTOR);
        "pthread_key_create": None,
        # int pthread_key_delete (pthread_key_t KEY);
        "pthread_key_delete": None,
        # void *pthread_getspecific (pthread_key_t KEY);
        "*pthread_getspecific": None,
        # int pthread_setspecific (pthread_key_t KEY, const void *VALUE);
        "pthread_setspecific": None,
        # int pthread_getattr_default_np (pthread_attr_t *ATTR);
        "pthread_getattr_default_np": None,
        # int pthread_setattr_default_np (pthread_attr_t *ATTR);
        "pthread_setattr_default_np": None,
        # uint64_t __ppc_get_timebase (void);
        "__ppc_get_timebase": SimTypeFunction([ ], SimTypeLongLong(signed=False, label=None), label=None),
        # uint64_t __ppc_get_timebase_freq (void);
        "__ppc_get_timebase_freq": SimTypeFunction([ ], SimTypeLongLong(signed=False, label=None), label=None),
        # void __ppc_yield (void);
        "__ppc_yield": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_mdoio (void);
        "__ppc_mdoio": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_mdoom (void);
        "__ppc_mdoom": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_set_ppr_med (void);
        "__ppc_set_ppr_med": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_set_ppr_low (void);
        "__ppc_set_ppr_low": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_set_ppr_med_low (void);
        "__ppc_set_ppr_med_low": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_set_ppr_very_low (void);
        "__ppc_set_ppr_very_low": SimTypeFunction([ ], SimTypeBottom(), label=None),
        # void __ppc_set_ppr_med_high (void);
        "__ppc_set_ppr_med_high": SimTypeFunction([ ], SimTypeBottom(), label=None),
    }


proto_count = 0
unsupported_count = 0

for name, proto in _libc_decls.items():
    if proto is not None:
        libc.set_prototype(name, proto)
        proto_count += 1
    else:
        unsupported_count += 1

_l.debug("Libc provides %d function prototypes, and has %d unsupported function prototypes.",
         proto_count, unsupported_count)


#
# function prototypes in strings
#

_libc_c_decls = \
    [
        "char * strerror (int ERRNUM);",
        "char * strerror_r (int ERRNUM, char *BUF, size_t N);",
        "void perror (const char *MESSAGE);",
        "void error (int STATUS, int ERRNUM, const char *FORMAT, ...);",
        "void error_at_line (int STATUS, int ERRNUM, const char *FNAME, unsigned int LINENO, const char *FORMAT, ...);",
        "void warn (const char *FORMAT, ...);",
        "void vwarn (const char *FORMAT, va_list AP);",
        "void warnx (const char *FORMAT, ...);",
        "void vwarnx (const char *FORMAT, va_list AP);",
        "void err (int STATUS, const char *FORMAT, ...);",
        "void verr (int STATUS, const char *FORMAT, va_list AP);",
        "void errx (int STATUS, const char *FORMAT, ...);",
        "void verrx (int STATUS, const char *FORMAT, va_list AP);",
        "void * malloc (size_t SIZE);",
        "void free (void *PTR);",
        "void * realloc (void *PTR, size_t NEWSIZE);",
        "void * reallocarray (void *PTR, size_t NMEMB, size_t SIZE);",
        "void * calloc (size_t COUNT, size_t ELTSIZE);",
        "void * aligned_alloc (size_t ALIGNMENT, size_t SIZE);",
        "void * memalign (size_t BOUNDARY, size_t SIZE);",
        "int posix_memalign (void **MEMPTR, size_t ALIGNMENT, size_t SIZE);",
        "void * valloc (size_t SIZE);",
        "int mallopt (int PARAM, int VALUE);",
        "int mcheck (void (*ABORTFN) (enum mcheck_status STATUS));",
        "enum mcheck_status mprobe (void *POINTER);",
        "struct mallinfo mallinfo (void);",
        "void mtrace (void);",
        "void muntrace (void);",
        "int obstack_init (struct obstack *OBSTACK_PTR);",
        "void * obstack_alloc (struct obstack *OBSTACK_PTR, int SIZE);",
        "void * obstack_copy (struct obstack *OBSTACK_PTR, void *ADDRESS, int SIZE);",
        "void * obstack_copy0 (struct obstack *OBSTACK_PTR, void *ADDRESS, int SIZE);",
        "void obstack_free (struct obstack *OBSTACK_PTR, void *OBJECT);",
        "void obstack_blank (struct obstack *OBSTACK_PTR, int SIZE);",
        "void obstack_grow (struct obstack *OBSTACK_PTR, void *DATA, int SIZE);",
        "void obstack_grow0 (struct obstack *OBSTACK_PTR, void *DATA, int SIZE);",
        "void obstack_1grow (struct obstack *OBSTACK_PTR, char C);",
        "void obstack_ptr_grow (struct obstack *OBSTACK_PTR, void *DATA);",
        "void obstack_int_grow (struct obstack *OBSTACK_PTR, int DATA);",
        "void * obstack_finish (struct obstack *OBSTACK_PTR);",
        "int obstack_object_size (struct obstack *OBSTACK_PTR);",
        "int obstack_room (struct obstack *OBSTACK_PTR);",
        "void obstack_1grow_fast (struct obstack *OBSTACK_PTR, char C);",
        "void obstack_ptr_grow_fast (struct obstack *OBSTACK_PTR, void *DATA);",
        "void obstack_int_grow_fast (struct obstack *OBSTACK_PTR, int DATA);",
        "void obstack_blank_fast (struct obstack *OBSTACK_PTR, int SIZE);",
        "void * obstack_base (struct obstack *OBSTACK_PTR);",
        "int obstack_object_size (struct obstack *OBSTACK_PTR);",
        "void * alloca (size_t SIZE);",
        "int brk (void *ADDR);",
        "void *sbrk (ptrdiff_t DELTA);",
        "int mlock (const void *ADDR, size_t LEN);",
        "int munlock (const void *ADDR, size_t LEN);",
        "int mlockall (int FLAGS);",
        "int munlockall (void);",
        "int islower (int C);",
        "int isupper (int C);",
        "int isalpha (int C);",
        "int isdigit (int C);",
        "int isalnum (int C);",
        "int isxdigit (int C);",
        "int ispunct (int C);",
        "int isspace (int C);",
        "int isblank (int C);",
        "int isgraph (int C);",
        "int isprint (int C);",
        "int iscntrl (int C);",
        "int isascii (int C);",
        "int tolower (int C);",
        "int toupper (int C);",
        "int toascii (int C);",
        "int _tolower (int C);",
        "int _toupper (int C);",
        "wctype_t wctype (const char *PROPERTY);",
        "int iswctype (wint_t WC, wctype_t DESC);",
        "int iswalnum (wint_t WC);",
        "int iswalpha (wint_t WC);",
        "int iswcntrl (wint_t WC);",
        "int iswdigit (wint_t WC);",
        "int iswgraph (wint_t WC);",
        "int iswlower (wint_t WC);",
        "int iswprint (wint_t WC);",
        "int iswpunct (wint_t WC);",
        "int iswspace (wint_t WC);",
        "int iswupper (wint_t WC);",
        "int iswxdigit (wint_t WC);",
        "int iswblank (wint_t WC);",
        "wctrans_t wctrans (const char *PROPERTY);",
        "wint_t towctrans (wint_t WC, wctrans_t DESC);",
        "wint_t towlower (wint_t WC);",
        "wint_t towupper (wint_t WC);",
        "size_t strlen (const char *S);",
        "size_t wcslen (const wchar_t *WS);",
        "size_t strnlen (const char *S, size_t MAXLEN);",
        "size_t wcsnlen (const wchar_t *WS, size_t MAXLEN);",
        "void * memcpy (void *restrict TO, const void *restrict FROM, size_t SIZE);",
        "wchar_t * wmemcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);",
        "void * mempcpy (void *restrict TO, const void *restrict FROM, size_t SIZE);",
        "wchar_t * wmempcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);",
        "void * memmove (void *TO, const void *FROM, size_t SIZE);",
        "wchar_t * wmemmove (wchar_t *WTO, const wchar_t *WFROM, size_t SIZE);",
        "void * memccpy (void *restrict TO, const void *restrict FROM, int C, size_t SIZE);",
        "void * memset (void *BLOCK, int C, size_t SIZE);",
        "wchar_t * wmemset (wchar_t *BLOCK, wchar_t WC, size_t SIZE);",
        "char * strcpy (char *restrict TO, const char *restrict FROM);",
        "wchar_t * wcscpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM);",
        "char * strdup (const char *S);",
        "wchar_t * wcsdup (const wchar_t *WS);",
        "char * stpcpy (char *restrict TO, const char *restrict FROM);",
        "wchar_t * wcpcpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM);",
        "void bcopy (const void *FROM, void *TO, size_t SIZE);",
        "void bzero (void *BLOCK, size_t SIZE);",
        "char * strcat (char *restrict TO, const char *restrict FROM);",
        "wchar_t * wcscat (wchar_t *restrict WTO, const wchar_t *restrict WFROM);",
        "char * strncpy (char *restrict TO, const char *restrict FROM, size_t SIZE);",
        "wchar_t * wcsncpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);",
        "char * strndup (const char *S, size_t SIZE);",
        "char * stpncpy (char *restrict TO, const char *restrict FROM, size_t SIZE);",
        "wchar_t * wcpncpy (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);",
        "char * strncat (char *restrict TO, const char *restrict FROM, size_t SIZE);",
        "wchar_t * wcsncat (wchar_t *restrict WTO, const wchar_t *restrict WFROM, size_t SIZE);",
        "int memcmp (const void *A1, const void *A2, size_t SIZE);",
        "int wmemcmp (const wchar_t *A1, const wchar_t *A2, size_t SIZE);",
        "int strcmp (const char *S1, const char *S2);",
        "int wcscmp (const wchar_t *WS1, const wchar_t *WS2);",
        "int strcasecmp (const char *S1, const char *S2);",
        "int wcscasecmp (const wchar_t *WS1, const wchar_t *WS2);",
        "int strncmp (const char *S1, const char *S2, size_t SIZE);",
        "int wcsncmp (const wchar_t *WS1, const wchar_t *WS2, size_t SIZE);",
        "int strncasecmp (const char *S1, const char *S2, size_t N);",
        "int wcsncasecmp (const wchar_t *WS1, const wchar_t *S2, size_t N);",
        "int strverscmp (const char *S1, const char *S2);",
        "int bcmp (const void *A1, const void *A2, size_t SIZE);",
        "int strcoll (const char *S1, const char *S2);",
        "int wcscoll (const wchar_t *WS1, const wchar_t *WS2);",
        "size_t strxfrm (char *restrict TO, const char *restrict FROM, size_t SIZE);",
        "size_t wcsxfrm (wchar_t *restrict WTO, const wchar_t *WFROM, size_t SIZE);",
        "void * memchr (const void *BLOCK, int C, size_t SIZE);",
        "wchar_t * wmemchr (const wchar_t *BLOCK, wchar_t WC, size_t SIZE);",
        "void * rawmemchr (const void *BLOCK, int C);",
        "void * memrchr (const void *BLOCK, int C, size_t SIZE);",
        "char * strchr (const char *STRING, int C);",
        "wchar_t * wcschr (const wchar_t *WSTRING, int WC);",
        "char * strchrnul (const char *STRING, int C);",
        "wchar_t * wcschrnul (const wchar_t *WSTRING, wchar_t WC);",
        "char * strrchr (const char *STRING, int C);",
        "wchar_t * wcsrchr (const wchar_t *WSTRING, wchar_t C);",
        "char * strstr (const char *HAYSTACK, const char *NEEDLE);",
        "wchar_t * wcsstr (const wchar_t *HAYSTACK, const wchar_t *NEEDLE);",
        "wchar_t * wcswcs (const wchar_t *HAYSTACK, const wchar_t *NEEDLE);",
        "char * strcasestr (const char *HAYSTACK, const char *NEEDLE);",
        "void * memmem (const void *HAYSTACK, size_t HAYSTACK_LEN, const void *NEEDLE, size_t NEEDLE_LEN);",
        "size_t strspn (const char *STRING, const char *SKIPSET);",
        "size_t wcsspn (const wchar_t *WSTRING, const wchar_t *SKIPSET);",
        "size_t strcspn (const char *STRING, const char *STOPSET);",
        "size_t wcscspn (const wchar_t *WSTRING, const wchar_t *STOPSET);",
        "char * strpbrk (const char *STRING, const char *STOPSET);",
        "wchar_t * wcspbrk (const wchar_t *WSTRING, const wchar_t *STOPSET);",
        "char * index (const char *STRING, int C);",
        "char * rindex (const char *STRING, int C);",
        "char * strtok (char *restrict NEWSTRING, const char *restrict DELIMITERS);",
        "wchar_t * wcstok (wchar_t *NEWSTRING, const wchar_t *DELIMITERS, wchar_t **SAVE_PTR);",
        "char * strtok_r (char *NEWSTRING, const char *DELIMITERS, char **SAVE_PTR);",
        "char * strsep (char **STRING_PTR, const char *DELIMITER);",
        "char * basename (const char *FILENAME);",
        "char * basename (char *PATH);",
        "char * dirname (char *PATH);",
        "void explicit_bzero (void *BLOCK, size_t LEN);",
        "char * strfry (char *STRING);",
        "void * memfrob (void *MEM, size_t LENGTH);",
        "char * l64a (long int N);",
        "long int a64l (const char *STRING);",
        "error_t argz_create (char *const ARGV[], char **ARGZ, size_t *ARGZ_LEN);",
        "error_t argz_create_sep (const char *STRING, int SEP, char **ARGZ, size_t *ARGZ_LEN);",
        "size_t argz_count (const char *ARGZ, size_t ARGZ_LEN);",
        "void argz_extract (const char *ARGZ, size_t ARGZ_LEN, char **ARGV);",
        "void argz_stringify (char *ARGZ, size_t LEN, int SEP);",
        "error_t argz_add (char **ARGZ, size_t *ARGZ_LEN, const char *STR);",
        "error_t argz_add_sep (char **ARGZ, size_t *ARGZ_LEN, const char *STR, int DELIM);",
        "error_t argz_append (char **ARGZ, size_t *ARGZ_LEN, const char *BUF, size_t BUF_LEN);",
        "void argz_delete (char **ARGZ, size_t *ARGZ_LEN, char *ENTRY);",
        "error_t argz_insert (char **ARGZ, size_t *ARGZ_LEN, char *BEFORE, const char *ENTRY);",
        "char * argz_next (const char *ARGZ, size_t ARGZ_LEN, const char *ENTRY);",
        "error_t argz_replace (char **ARGZ, size_t *ARGZ_LEN, const char *STR, const char *WITH, unsigned *REPLACE_COUNT);",
        "char * envz_entry (const char *ENVZ, size_t ENVZ_LEN, const char *NAME);",
        "char * envz_get (const char *ENVZ, size_t ENVZ_LEN, const char *NAME);",
        "error_t envz_add (char **ENVZ, size_t *ENVZ_LEN, const char *NAME, const char *VALUE);",
        "error_t envz_merge (char **ENVZ, size_t *ENVZ_LEN, const char *ENVZ2, size_t ENVZ2_LEN, int OVERRIDE);",
        "void envz_strip (char **ENVZ, size_t *ENVZ_LEN);",
        "void envz_remove (char **ENVZ, size_t *ENVZ_LEN, const char *NAME);",
        "int mbsinit (const mbstate_t *PS);",
        "wint_t btowc (int C);",
        "int wctob (wint_t C);",
        "size_t mbrtowc (wchar_t *restrict PWC, const char *restrict S, size_t N, mbstate_t *restrict PS);",
        "size_t mbrlen (const char *restrict S, size_t N, mbstate_t *PS);",
        "size_t wcrtomb (char *restrict S, wchar_t WC, mbstate_t *restrict PS);",
        "size_t mbsrtowcs (wchar_t *restrict DST, const char **restrict SRC, size_t LEN, mbstate_t *restrict PS);",
        "size_t wcsrtombs (char *restrict DST, const wchar_t **restrict SRC, size_t LEN, mbstate_t *restrict PS);",
        "size_t mbsnrtowcs (wchar_t *restrict DST, const char **restrict SRC, size_t NMC, size_t LEN, mbstate_t *restrict PS);",
        "size_t wcsnrtombs (char *restrict DST, const wchar_t **restrict SRC, size_t NWC, size_t LEN, mbstate_t *restrict PS);",
        "int mbtowc (wchar_t *restrict RESULT, const char *restrict STRING, size_t SIZE);",
        "int wctomb (char *STRING, wchar_t WCHAR);",
        "int mblen (const char *STRING, size_t SIZE);",
        "size_t mbstowcs (wchar_t *WSTRING, const char *STRING, size_t SIZE);",
        "size_t wcstombs (char *STRING, const wchar_t *WSTRING, size_t SIZE);",
        "iconv_t iconv_open (const char *TOCODE, const char *FROMCODE);",
        "int iconv_close (iconv_t CD);",
        "size_t iconv (iconv_t CD, char **INBUF, size_t *INBYTESLEFT, char **OUTBUF, size_t *OUTBYTESLEFT);",
        "char * setlocale (int CATEGORY, const char *LOCALE);",
        "struct lconv * localeconv (void);",
        "char * nl_langinfo (nl_item ITEM);",
        "ssize_t strfmon (char *S, size_t MAXSIZE, const char *FORMAT, ...);",
        "int rpmatch (const char *RESPONSE);",
        "nl_catd catopen (const char *CAT_NAME, int FLAG);",
        "char * catgets (nl_catd CATALOG_DESC, int SET, int MESSAGE, const char *STRING);",
        "int catclose (nl_catd CATALOG_DESC);",
        "char * gettext (const char *MSGID);",
        "char * dgettext (const char *DOMAINNAME, const char *MSGID);",
        "char * dcgettext (const char *DOMAINNAME, const char *MSGID, int CATEGORY);",
        "char * textdomain (const char *DOMAINNAME);",
        "char * bindtextdomain (const char *DOMAINNAME, const char *DIRNAME);",
        "char * ngettext (const char *MSGID1, const char *MSGID2, unsigned long int N);",
        "char * dngettext (const char *DOMAIN, const char *MSGID1, const char *MSGID2, unsigned long int N);",
        "char * dcngettext (const char *DOMAIN, const char *MSGID1, const char *MSGID2, unsigned long int N, int CATEGORY);",
        "char * bind_textdomain_codeset (const char *DOMAINNAME, const char *CODESET);",
        "void * lfind (const void *KEY, const void *BASE, size_t *NMEMB, size_t SIZE, comparison_fn_t COMPAR);",
        "void * lsearch (const void *KEY, void *BASE, size_t *NMEMB, size_t SIZE, comparison_fn_t COMPAR);",
        "void * bsearch (const void *KEY, const void *ARRAY, size_t COUNT, size_t SIZE, comparison_fn_t COMPARE);",
        "void qsort (void *ARRAY, size_t COUNT, size_t SIZE, comparison_fn_t COMPARE);",
        "int hcreate (size_t NEL);",
        "void hdestroy (void);",
        "ENTRY * hsearch (ENTRY ITEM, ACTION ACTION);",
        "int hcreate_r (size_t NEL, struct hsearch_data *HTAB);",
        "void hdestroy_r (struct hsearch_data *HTAB);",
        "int hsearch_r (ENTRY ITEM, ACTION ACTION, ENTRY **RETVAL, struct hsearch_data *HTAB);",
        "void * tsearch (const void *KEY, void **ROOTP, comparison_fn_t COMPAR);",
        "void * tfind (const void *KEY, void *const *ROOTP, comparison_fn_t COMPAR);",
        "void * tdelete (const void *KEY, void **ROOTP, comparison_fn_t COMPAR);",
        "void tdestroy (void *VROOT, __free_fn_t FREEFCT);",
        "void twalk (const void *ROOT, __action_fn_t ACTION);",
        "int fnmatch (const char *PATTERN, const char *STRING, int FLAGS);",
        "int glob (const char *PATTERN, int FLAGS, int (*ERRFUNC) (const char *FILENAME, int ERROR_CODE), glob_t *VECTOR_PTR);",
        "int glob64 (const char *PATTERN, int FLAGS, int (*ERRFUNC) (const char *FILENAME, int ERROR_CODE), glob64_t *VECTOR_PTR);",
        "void globfree (glob_t *PGLOB);",
        "void globfree64 (glob64_t *PGLOB);",
        "int regcomp (regex_t *restrict COMPILED, const char *restrict PATTERN, int CFLAGS);",
        "int regexec (const regex_t *restrict COMPILED, const char *restrict STRING, size_t NMATCH, regmatch_t MATCHPTR[restrict], int EFLAGS);",
        "void regfree (regex_t *COMPILED);",
        "size_t regerror (int ERRCODE, const regex_t *restrict COMPILED, char *restrict BUFFER, size_t LENGTH);",
        "int wordexp (const char *WORDS, wordexp_t *WORD_VECTOR_PTR, int FLAGS);",
        "void wordfree (wordexp_t *WORD_VECTOR_PTR);",

        # TODO: Support FILE*

        "FILE * fopen (const char *FILENAME, const char *OPENTYPE);",
        "FILE * fopen64 (const char *FILENAME, const char *OPENTYPE);",
        "FILE * freopen (const char *FILENAME, const char *OPENTYPE, FILE *STREAM);",
        "FILE * freopen64 (const char *FILENAME, const char *OPENTYPE, FILE *STREAM);",
        "int __freadable (FILE *STREAM);",
        "int __fwritable (FILE *STREAM);",
        "int __freading (FILE *STREAM);",
        "int __fwriting (FILE *STREAM);",
        "int fclose (FILE *STREAM);",
        "int fcloseall (void);",
        "void flockfile (FILE *STREAM);",
        "int ftrylockfile (FILE *STREAM);",
        "void funlockfile (FILE *STREAM);",
        "int __fsetlocking (FILE *STREAM, int TYPE);",
        "int fwide (FILE *STREAM, int MODE);",
        "int fputc (int C, FILE *STREAM);",
        "wint_t fputwc (wchar_t WC, FILE *STREAM);",
        "int fputc_unlocked (int C, FILE *STREAM);",
        "wint_t fputwc_unlocked (wchar_t WC, FILE *STREAM);",
        "int putc (int C, FILE *STREAM);",
        "wint_t putwc (wchar_t WC, FILE *STREAM);",
        "int putc_unlocked (int C, FILE *STREAM);",
        "wint_t putwc_unlocked (wchar_t WC, FILE *STREAM);",
        "int putchar (int C);",
        "wint_t putwchar (wchar_t WC);",
        "int putchar_unlocked (int C);",
        "wint_t putwchar_unlocked (wchar_t WC);",
        "int fputs (const char *S, FILE *STREAM);",
        "int fputws (const wchar_t *WS, FILE *STREAM);",
        "int fputs_unlocked (const char *S, FILE *STREAM);",
        "int fputws_unlocked (const wchar_t *WS, FILE *STREAM);",
        "int puts (const char *S);",
        "int putw (int W, FILE *STREAM);",
        "int fgetc (FILE *STREAM);",
        "wint_t fgetwc (FILE *STREAM);",
        "int fgetc_unlocked (FILE *STREAM);",
        "wint_t fgetwc_unlocked (FILE *STREAM);",
        "int getc (FILE *STREAM);",
        "wint_t getwc (FILE *STREAM);",
        "int getc_unlocked (FILE *STREAM);",
        "wint_t getwc_unlocked (FILE *STREAM);",
        "int getchar (void);",
        "wint_t getwchar (void);",
        "int getchar_unlocked (void);",
        "wint_t getwchar_unlocked (void);",
        "int getw (FILE *STREAM);",
        "ssize_t getline (char **LINEPTR, size_t *N, FILE *STREAM);",
        "ssize_t getdelim (char **LINEPTR, size_t *N, int DELIMITER, FILE *STREAM);",
        "char * fgets (char *S, int COUNT, FILE *STREAM);",
        "wchar_t * fgetws (wchar_t *WS, int COUNT, FILE *STREAM);",
        "char * fgets_unlocked (char *S, int COUNT, FILE *STREAM);",
        "wchar_t * fgetws_unlocked (wchar_t *WS, int COUNT, FILE *STREAM);",
        "int ungetc (int C, FILE *STREAM);",
        "wint_t ungetwc (wint_t WC, FILE *STREAM);",
        "size_t fread (void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);",
        "size_t fread_unlocked (void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);",
        "size_t fwrite (const void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);",
        "size_t fwrite_unlocked (const void *DATA, size_t SIZE, size_t COUNT, FILE *STREAM);",


        "int printf (const char *TEMPLATE, ...);",
        "int wprintf (const wchar_t *TEMPLATE, ...);",
        "int fprintf (FILE *STREAM, const char *TEMPLATE, ...);",
        "int fwprintf (FILE *STREAM, const wchar_t *TEMPLATE, ...);",
        "int sprintf (char *S, const char *TEMPLATE, ...);",
        "int swprintf (wchar_t *WS, size_t SIZE, const wchar_t *TEMPLATE, ...);",
        "int snprintf (char *S, size_t SIZE, const char *TEMPLATE, ...);",
        "int asprintf (char **PTR, const char *TEMPLATE, ...);",
        "int obstack_printf (struct obstack *OBSTACK, const char *TEMPLATE, ...);",
        "int vprintf (const char *TEMPLATE, va_list AP);",
        "int vwprintf (const wchar_t *TEMPLATE, va_list AP);",
        "int vfprintf (FILE *STREAM, const char *TEMPLATE, va_list AP);",
        "int vfwprintf (FILE *STREAM, const wchar_t *TEMPLATE, va_list AP);",
        "int vsprintf (char *S, const char *TEMPLATE, va_list AP);",
        "int vswprintf (wchar_t *WS, size_t SIZE, const wchar_t *TEMPLATE, va_list AP);",
        "int vsnprintf (char *S, size_t SIZE, const char *TEMPLATE, va_list AP);",
        "int vasprintf (char **PTR, const char *TEMPLATE, va_list AP);",
        "int obstack_vprintf (struct obstack *OBSTACK, const char *TEMPLATE, va_list AP);",
        "size_t parse_printf_format (const char *TEMPLATE, size_t N, int *ARGTYPES);",
        "int register_printf_function (int SPEC, printf_function HANDLER_FUNCTION, printf_arginfo_function ARGINFO_FUNCTION);",
        "int printf_size (FILE *FP, const struct printf_info *INFO, const void *const *ARGS);",
        "int printf_size_info (const struct printf_info *INFO, size_t N, int *ARGTYPES);",
        "int scanf (const char *TEMPLATE, ...);",
        "int wscanf (const wchar_t *TEMPLATE, ...);",
        "int fscanf (FILE *STREAM, const char *TEMPLATE, ...);",
        "int fwscanf (FILE *STREAM, const wchar_t *TEMPLATE, ...);",
        "int sscanf (const char *S, const char *TEMPLATE, ...);",
        "int swscanf (const wchar_t *WS, const wchar_t *TEMPLATE, ...);",
        "int vscanf (const char *TEMPLATE, va_list AP);",
        "int vwscanf (const wchar_t *TEMPLATE, va_list AP);",
        "int vfscanf (FILE *STREAM, const char *TEMPLATE, va_list AP);",
        "int vfwscanf (FILE *STREAM, const wchar_t *TEMPLATE, va_list AP);",
        "int vsscanf (const char *S, const char *TEMPLATE, va_list AP);",
        "int vswscanf (const wchar_t *S, const wchar_t *TEMPLATE, va_list AP);",
        "int feof (FILE *STREAM);",
        "int feof_unlocked (FILE *STREAM);",
        "int ferror (FILE *STREAM);",
        "int ferror_unlocked (FILE *STREAM);",
        "void clearerr (FILE *STREAM);",
        "void clearerr_unlocked (FILE *STREAM);",
        "long int ftell (FILE *STREAM);",
        "off_t ftello (FILE *STREAM);",
        "off64_t ftello64 (FILE *STREAM);",
        "int fseek (FILE *STREAM, long int OFFSET, int WHENCE);",
        "int fseeko (FILE *STREAM, off_t OFFSET, int WHENCE);",
        "int fseeko64 (FILE *STREAM, off64_t OFFSET, int WHENCE);",
        "void rewind (FILE *STREAM);",
        "int fgetpos (FILE *STREAM, fpos_t *POSITION);",
        "int fgetpos64 (FILE *STREAM, fpos64_t *POSITION);",
        "int fsetpos (FILE *STREAM, const fpos_t *POSITION);",
        "int fsetpos64 (FILE *STREAM, const fpos64_t *POSITION);",
        "int fflush (FILE *STREAM);",
        "int fflush_unlocked (FILE *STREAM);",
        "void _flushlbf (void);",
        "void __fpurge (FILE *STREAM);",
        "int setvbuf (FILE *STREAM, char *BUF, int MODE, size_t SIZE);",
        "void setbuf (FILE *STREAM, char *BUF);",
        "void setbuffer (FILE *STREAM, char *BUF, size_t SIZE);",
        "void setlinebuf (FILE *STREAM);",
        "int __flbf (FILE *STREAM);",
        "size_t __fbufsize (FILE *STREAM);",
        "size_t __fpending (FILE *STREAM);",
        "FILE * fmemopen (void *BUF, size_t SIZE, const char *OPENTYPE);",
        "FILE * open_memstream (char **PTR, size_t *SIZELOC);",
        "FILE * fopencookie (void *COOKIE, const char *OPENTYPE, cookie_io_functions_t IO-FUNCTIONS);",
        "int fmtmsg (long int CLASSIFICATION, const char *LABEL, int SEVERITY, const char *TEXT, const char *ACTION, const char *TAG);",
        "int addseverity (int SEVERITY, const char *STRING);",
        "int open (const char *FILENAME, int FLAGS, mode_t MODE);",
        "int open64 (const char *FILENAME, int FLAGS, mode_t MODE);",
        "int close (int FILEDES);",
        "ssize_t read (int FILEDES, void *BUFFER, size_t SIZE);",
        "ssize_t pread (int FILEDES, void *BUFFER, size_t SIZE, off_t OFFSET);",
        "ssize_t pread64 (int FILEDES, void *BUFFER, size_t SIZE, off64_t OFFSET);",
        "ssize_t write (int FILEDES, const void *BUFFER, size_t SIZE);",
        "ssize_t pwrite (int FILEDES, const void *BUFFER, size_t SIZE, off_t OFFSET);",
        "ssize_t pwrite64 (int FILEDES, const void *BUFFER, size_t SIZE, off64_t OFFSET);",
        "ssize_t preadv (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET);",
        "ssize_t preadv64 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET);",
        "ssize_t pwritev (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET);",
        "ssize_t pwritev64 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET);",
        "ssize_t preadv2 (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET, int FLAGS);",
        "ssize_t preadv64v2 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET, int FLAGS);",
        "ssize_t pwritev2 (int FD, const struct iovec *IOV, int IOVCNT, off_t OFFSET, int FLAGS);",
        "ssize_t pwritev64v2 (int FD, const struct iovec *IOV, int IOVCNT, off64_t OFFSET, int FLAGS);",
        "off_t lseek (int FILEDES, off_t OFFSET, int WHENCE);",
        "off64_t lseek64 (int FILEDES, off64_t OFFSET, int WHENCE);",
        "FILE * fdopen (int FILEDES, const char *OPENTYPE);",
        "int fileno (FILE *STREAM);",
        "int fileno_unlocked (FILE *STREAM);",
        "ssize_t readv (int FILEDES, const struct iovec *VECTOR, int COUNT);",
        "ssize_t writev (int FILEDES, const struct iovec *VECTOR, int COUNT);",
        "void * mmap (void *ADDRESS, size_t LENGTH, int PROTECT, int FLAGS, int FILEDES, off_t OFFSET);",
        "void * mmap64 (void *ADDRESS, size_t LENGTH, int PROTECT, int FLAGS, int FILEDES, off64_t OFFSET);",
        "int munmap (void *ADDR, size_t LENGTH);",
        "int msync (void *ADDRESS, size_t LENGTH, int FLAGS);",
        "void * mremap (void *ADDRESS, size_t LENGTH, size_t NEW_LENGTH, int FLAG);",
        "int madvise (void *ADDR, size_t LENGTH, int ADVICE);",
        "int shm_open (const char *NAME, int OFLAG, mode_t MODE);",
        "int shm_unlink (const char *NAME);",
        "int select (int NFDS, fd_set *READ_FDS, fd_set *WRITE_FDS, fd_set *EXCEPT_FDS, struct timeval *TIMEOUT);",
        "void sync (void);",
        "int fsync (int FILDES);",
        "int fdatasync (int FILDES);",
        "int aio_read (struct aiocb *AIOCBP);",
        "int aio_read64 (struct aiocb64 *AIOCBP);",
        "int aio_write (struct aiocb *AIOCBP);",
        "int aio_write64 (struct aiocb64 *AIOCBP);",
        "int lio_listio (int MODE, struct aiocb *const LIST[], int NENT, struct sigevent *SIG);",
        "int lio_listio64 (int MODE, struct aiocb64 *const LIST[], int NENT, struct sigevent *SIG);",
        "int aio_error (const struct aiocb *AIOCBP);",
        "int aio_error64 (const struct aiocb64 *AIOCBP);",
        "ssize_t aio_return (struct aiocb *AIOCBP);",
        "ssize_t aio_return64 (struct aiocb64 *AIOCBP);",
        "int aio_fsync (int OP, struct aiocb *AIOCBP);",
        "int aio_fsync64 (int OP, struct aiocb64 *AIOCBP);",
        "int aio_suspend (const struct aiocb *const LIST[], int NENT, const struct timespec *TIMEOUT);",
        "int aio_suspend64 (const struct aiocb64 *const LIST[], int NENT, const struct timespec *TIMEOUT);",
        "int aio_cancel (int FILDES, struct aiocb *AIOCBP);",
        "int aio_cancel64 (int FILDES, struct aiocb64 *AIOCBP);",
        "void aio_init (const struct aioinit *INIT);",
        "int fcntl (int FILEDES, int COMMAND, ...);",
        "int dup (int OLD);",
        "int dup2 (int OLD, int NEW);",
        "int ioctl (int FILEDES, int COMMAND, ...);",
        "char * getcwd (char *BUFFER, size_t SIZE);",
        "char * get_current_dir_name (void);",
        "int chdir (const char *FILENAME);",
        "int fchdir (int FILEDES);",
        "int IFTODT (mode_t MODE);",
        "mode_t DTTOIF (int DTYPE);",

        # TODO: Support DIR*

        "DIR * opendir (const char *DIRNAME);",
        "DIR * fdopendir (int FD);",
        "int dirfd (DIR *DIRSTREAM);",
        "struct dirent * readdir (DIR *DIRSTREAM);",
        "int readdir_r (DIR *DIRSTREAM, struct dirent *ENTRY, struct dirent **RESULT);",
        "struct dirent64 * readdir64 (DIR *DIRSTREAM);",
        "int readdir64_r (DIR *DIRSTREAM, struct dirent64 *ENTRY, struct dirent64 **RESULT);",
        "int closedir (DIR *DIRSTREAM);",
        "void rewinddir (DIR *DIRSTREAM);",
        "long int telldir (DIR *DIRSTREAM);",
        "void seekdir (DIR *DIRSTREAM, long int POS);",
        "int scandir (const char *DIR, struct dirent ***NAMELIST, int (*SELECTOR);",
        "int alphasort (const struct dirent **A, const struct dirent **B);",
        "int versionsort (const struct dirent **A, const struct dirent **B);",
        "int scandir64 (const char *DIR, struct dirent64 ***NAMELIST, int (*SELECTOR);",
        "int alphasort64 (const struct dirent64 **A, const struct dirent **B);",
        "int versionsort64 (const struct dirent64 **A, const struct dirent64 **B);",
        "int ftw (const char *FILENAME, __ftw_func_t FUNC, int DESCRIPTORS);",
        "int ftw64 (const char *FILENAME, __ftw64_func_t FUNC, int DESCRIPTORS);",
        "int nftw (const char *FILENAME, __nftw_func_t FUNC, int DESCRIPTORS, int FLAG);",
        "int nftw64 (const char *FILENAME, __nftw64_func_t FUNC, int DESCRIPTORS, int FLAG);",
        "int link (const char *OLDNAME, const char *NEWNAME);",
        "int symlink (const char *OLDNAME, const char *NEWNAME);",
        "ssize_t readlink (const char *FILENAME, char *BUFFER, size_t SIZE);",
        "char * canonicalize_file_name (const char *NAME);",
        "char * realpath (const char *restrict NAME, char *restrict RESOLVED);",
        "int unlink (const char *FILENAME);",
        "int rmdir (const char *FILENAME);",
        "int remove (const char *FILENAME);",
        "int rename (const char *OLDNAME, const char *NEWNAME);",
        "int mkdir (const char *FILENAME, mode_t MODE);",
        "int stat (const char *FILENAME, struct stat *BUF);",
        "int stat64 (const char *FILENAME, struct stat64 *BUF);",
        "int fstat (int FILEDES, struct stat *BUF);",
        "int fstat64 (int FILEDES, struct stat64 *BUF);",
        "int lstat (const char *FILENAME, struct stat *BUF);",
        "int lstat64 (const char *FILENAME, struct stat64 *BUF);",
        "int chown (const char *FILENAME, uid_t OWNER, gid_t GROUP);",
        "int fchown (int FILEDES, uid_t OWNER, gid_t GROUP);",
        "mode_t umask (mode_t MASK);",
        "mode_t getumask (void);",
        "int chmod (const char *FILENAME, mode_t MODE);",
        "int fchmod (int FILEDES, mode_t MODE);",
        "int access (const char *FILENAME, int HOW);",
        "int utime (const char *FILENAME, const struct utimbuf *TIMES);",
        "int utimes (const char *FILENAME, const struct timeval TVP[2]);",
        "int lutimes (const char *FILENAME, const struct timeval TVP[2]);",
        "int futimes (int FD, const struct timeval TVP[2]);",
        "int truncate (const char *FILENAME, off_t LENGTH);",
        "int truncate64 (const char *NAME, off64_t LENGTH);",
        "int ftruncate (int FD, off_t LENGTH);",
        "int ftruncate64 (int ID, off64_t LENGTH);",
        "int posix_fallocate (int FD, off_t OFFSET, off_t LENGTH);",
        "int posix_fallocate64 (int FD, off64_t OFFSET, off64_t LENGTH);",
        "int mknod (const char *FILENAME, mode_t MODE, dev_t DEV);",
        "FILE * tmpfile (void);",
        "FILE * tmpfile64 (void);",
        "char * tmpnam (char *RESULT);",
        "char * tmpnam_r (char *RESULT);",
        "char * tempnam (const char *DIR, const char *PREFIX);",
        "char * mktemp (char *TEMPLATE);",
        "int mkstemp (char *TEMPLATE);",
        "char * mkdtemp (char *TEMPLATE);",
        "int pipe (int FILEDES[2]);",
        "FILE * popen (const char *COMMAND, const char *MODE);",
        "int pclose (FILE *STREAM);",
        "int mkfifo (const char *FILENAME, mode_t MODE);",
        "int bind (int SOCKET, struct sockaddr *ADDR, socklen_t LENGTH);",
        "int getsockname (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);",
        "unsigned int if_nametoindex (const char *IFNAME);",
        "char * if_indextoname (unsigned int IFINDEX, char *IFNAME);",
        "struct if_nameindex * if_nameindex (void);",
        "void if_freenameindex (struct if_nameindex *PTR);",
        "int inet_aton (const char *NAME, struct in_addr *ADDR);",
        "uint32_t inet_addr (const char *NAME);",
        "uint32_t inet_network (const char *NAME);",
        "char * inet_ntoa (struct in_addr ADDR);",
        "struct in_addr inet_makeaddr (uint32_t NET, uint32_t LOCAL);",
        "uint32_t inet_lnaof (struct in_addr ADDR);",
        "uint32_t inet_netof (struct in_addr ADDR);",
        "int inet_pton (int AF, const char *CP, void *BUF);",
        "const char * inet_ntop (int AF, const void *CP, char *BUF, socklen_t LEN);",
        "struct hostent * gethostbyname (const char *NAME);",
        "struct hostent * gethostbyname2 (const char *NAME, int AF);",
        "struct hostent * gethostbyaddr (const void *ADDR, socklen_t LENGTH, int FORMAT);",
        "int gethostbyname_r (const char *restrict NAME, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent **restrict RESULT, int * restrict H_ERRNOP);",
        "int gethostbyname2_r (const char *NAME, int AF, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent **restrict RESULT, int * restrict H_ERRNOP);",
        "int gethostbyaddr_r (const void *ADDR, socklen_t LENGTH, int FORMAT, struct hostent *restrict RESULT_BUF, char *restrict BUF, size_t BUFLEN, struct hostent ** restrict RESULT, int * restrict H_ERRNOP);",
        "void sethostent (int STAYOPEN);",
        "struct hostent * gethostent (void);",
        "void endhostent (void);",
        "struct servent * getservbyname (const char *NAME, const char *PROTO);",
        "struct servent * getservbyport (int PORT, const char *PROTO);",
        "void setservent (int STAYOPEN);",
        "struct servent * getservent (void);",
        "void endservent (void);",
        "uint16_t htons (uint16_t HOSTSHORT);",
        "uint16_t ntohs (uint16_t NETSHORT);",
        "uint32_t htonl (uint32_t HOSTLONG);",
        "uint32_t ntohl (uint32_t NETLONG);",
        "struct protoent * getprotobyname (const char *NAME);",
        "struct protoent * getprotobynumber (int PROTOCOL);",
        "void setprotoent (int STAYOPEN);",
        "struct protoent * getprotoent (void);",
        "void endprotoent (void);",
        "int socket (int NAMESPACE, int STYLE, int PROTOCOL);",
        "int shutdown (int SOCKET, int HOW);",
        "int socketpair (int NAMESPACE, int STYLE, int PROTOCOL, int FILEDES[2]);",
        "int connect (int SOCKET, struct sockaddr *ADDR, socklen_t LENGTH);",
        "int listen (int SOCKET, int N);",
        "int accept (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);",
        "int getpeername (int SOCKET, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);",
        "ssize_t send (int SOCKET, const void *BUFFER, size_t SIZE, int FLAGS);",
        "ssize_t recv (int SOCKET, void *BUFFER, size_t SIZE, int FLAGS);",
        "ssize_t sendto (int SOCKET, const void *BUFFER, size_t SIZE, int FLAGS, struct sockaddr *ADDR, socklen_t LENGTH);",
        "ssize_t recvfrom (int SOCKET, void *BUFFER, size_t SIZE, int FLAGS, struct sockaddr *ADDR, socklen_t *LENGTH_PTR);",
        "int getsockopt (int SOCKET, int LEVEL, int OPTNAME, void *OPTVAL, socklen_t *OPTLEN_PTR);",
        "int setsockopt (int SOCKET, int LEVEL, int OPTNAME, const void *OPTVAL, socklen_t OPTLEN);",
        "struct netent * getnetbyname (const char *NAME);",
        "struct netent * getnetbyaddr (uint32_t NET, int TYPE);",
        "void setnetent (int STAYOPEN);",
        "struct netent * getnetent (void);",
        "void endnetent (void);",
        "int isatty (int FILEDES);",
        "char * ttyname (int FILEDES);",
        "int ttyname_r (int FILEDES, char *BUF, size_t LEN);",
        "int tcgetattr (int FILEDES, struct termios *TERMIOS_P);",
        "int tcsetattr (int FILEDES, int WHEN, const struct termios *TERMIOS_P);",
        "speed_t cfgetospeed (const struct termios *TERMIOS_P);",
        "speed_t cfgetispeed (const struct termios *TERMIOS_P);",
        "int cfsetospeed (struct termios *TERMIOS_P, speed_t SPEED);",
        "int cfsetispeed (struct termios *TERMIOS_P, speed_t SPEED);",
        "int cfsetspeed (struct termios *TERMIOS_P, speed_t SPEED);",
        "void cfmakeraw (struct termios *TERMIOS_P);",
        "int gtty (int FILEDES, struct sgttyb *ATTRIBUTES);",
        "int stty (int FILEDES, const struct sgttyb *ATTRIBUTES);",
        "int tcsendbreak (int FILEDES, int DURATION);",
        "int tcdrain (int FILEDES);",
        "int tcflush (int FILEDES, int QUEUE);",
        "int tcflow (int FILEDES, int ACTION);",
        "int getpt (void);",
        "int grantpt (int FILEDES);",
        "int unlockpt (int FILEDES);",
        "char * ptsname (int FILEDES);",
        "int ptsname_r (int FILEDES, char *BUF, size_t LEN);",
        "int openpty (int *AMASTER, int *ASLAVE, char *NAME, const struct termios *TERMP, const struct winsize *WINP);",
        "int forkpty (int *AMASTER, char *NAME, const struct termios *TERMP, const struct winsize *WINP);",
        "void openlog (const char *IDENT, int OPTION, int FACILITY);",
        "void syslog (int FACILITY_PRIORITY, const char *FORMAT, ...);",
        "void vsyslog (int FACILITY_PRIORITY, const char *FORMAT, va_list ARGLIST);",
        "void closelog (void);",
        "int setlogmask (int MASK);",
        "double sin (double X);",
        "float sinf (float X);",

        # TODO: Support long double

        "long double sinl (long double X);",
        "_FloatN sinfN (_FloatN X);",
        "_FloatNx sinfNx (_FloatNx X);",
        "double cos (double X);",
        "float cosf (float X);",
        "long double cosl (long double X);",
        "_FloatN cosfN (_FloatN X);",
        "_FloatNx cosfNx (_FloatNx X);",
        "double tan (double X);",
        "float tanf (float X);",
        "long double tanl (long double X);",
        "_FloatN tanfN (_FloatN X);",
        "_FloatNx tanfNx (_FloatNx X);",
        "void sincos (double X, double *SINX, double *COSX);",
        "void sincosf (float X, float *SINX, float *COSX);",
        "void sincosl (long double X, long double *SINX, long double *COSX);",
        "_FloatN sincosfN (_FloatN X, _FloatN *SINX, _FloatN *COSX);",
        "_FloatNx sincosfNx (_FloatNx X, _FloatNx *SINX, _FloatNx *COSX);",
        "complex double csin (complex double Z);",
        "complex float csinf (complex float Z);",
        "complex long double csinl (complex long double Z);",
        "complex _FloatN csinfN (complex _FloatN Z);",
        "complex _FloatNx csinfNx (complex _FloatNx Z);",
        "complex double ccos (complex double Z);",
        "complex float ccosf (complex float Z);",
        "complex long double ccosl (complex long double Z);",
        "complex _FloatN ccosfN (complex _FloatN Z);",
        "complex _FloatNx ccosfNx (complex _FloatNx Z);",
        "complex double ctan (complex double Z);",
        "complex float ctanf (complex float Z);",
        "complex long double ctanl (complex long double Z);",
        "complex _FloatN ctanfN (complex _FloatN Z);",
        "complex _FloatNx ctanfNx (complex _FloatNx Z);",
        "double asin (double X);",
        "float asinf (float X);",
        "long double asinl (long double X);",
        "_FloatN asinfN (_FloatN X);",
        "_FloatNx asinfNx (_FloatNx X);",
        "double acos (double X);",
        "float acosf (float X);",
        "long double acosl (long double X);",
        "_FloatN acosfN (_FloatN X);",
        "_FloatNx acosfNx (_FloatNx X);",
        "double atan (double X);",
        "float atanf (float X);",
        "long double atanl (long double X);",
        "_FloatN atanfN (_FloatN X);",
        "_FloatNx atanfNx (_FloatNx X);",
        "double atan2 (double Y, double X);",
        "float atan2f (float Y, float X);",
        "long double atan2l (long double Y, long double X);",
        "_FloatN atan2fN (_FloatN Y, _FloatN X);",
        "_FloatNx atan2fNx (_FloatNx Y, _FloatNx X);",
        "complex double casin (complex double Z);",
        "complex float casinf (complex float Z);",
        "complex long double casinl (complex long double Z);",
        "complex _FloatN casinfN (complex _FloatN Z);",
        "complex _FloatNx casinfNx (complex _FloatNx Z);",
        "complex double cacos (complex double Z);",
        "complex float cacosf (complex float Z);",
        "complex long double cacosl (complex long double Z);",
        "complex _FloatN cacosfN (complex _FloatN Z);",
        "complex _FloatNx cacosfNx (complex _FloatNx Z);",
        "complex double catan (complex double Z);",
        "complex float catanf (complex float Z);",
        "complex long double catanl (complex long double Z);",
        "complex _FloatN catanfN (complex _FloatN Z);",
        "complex _FloatNx catanfNx (complex _FloatNx Z);",
        "double exp (double X);",
        "float expf (float X);",
        "long double expl (long double X);",
        "_FloatN expfN (_FloatN X);",
        "_FloatNx expfNx (_FloatNx X);",
        "double exp2 (double X);",
        "float exp2f (float X);",
        "long double exp2l (long double X);",
        "_FloatN exp2fN (_FloatN X);",
        "_FloatNx exp2fNx (_FloatNx X);",
        "double exp10 (double X);",
        "float exp10f (float X);",
        "long double exp10l (long double X);",
        "_FloatN exp10fN (_FloatN X);",
        "_FloatNx exp10fNx (_FloatNx X);",
        "double pow10 (double X);",
        "float pow10f (float X);",
        "long double pow10l (long double X);",
        "double log (double X);",
        "float logf (float X);",
        "long double logl (long double X);",
        "_FloatN logfN (_FloatN X);",
        "_FloatNx logfNx (_FloatNx X);",
        "double log10 (double X);",
        "float log10f (float X);",
        "long double log10l (long double X);",
        "_FloatN log10fN (_FloatN X);",
        "_FloatNx log10fNx (_FloatNx X);",
        "double log2 (double X);",
        "float log2f (float X);",
        "long double log2l (long double X);",
        "_FloatN log2fN (_FloatN X);",
        "_FloatNx log2fNx (_FloatNx X);",
        "double logb (double X);",
        "float logbf (float X);",
        "long double logbl (long double X);",
        "_FloatN logbfN (_FloatN X);",
        "_FloatNx logbfNx (_FloatNx X);",
        "int ilogb (double X);",
        "int ilogbf (float X);",
        "int ilogbl (long double X);",
        "int ilogbfN (_FloatN X);",
        "int ilogbfNx (_FloatNx X);",
        "long int llogb (double X);",
        "long int llogbf (float X);",
        "long int llogbl (long double X);",
        "long int llogbfN (_FloatN X);",
        "long int llogbfNx (_FloatNx X);",
        "double pow (double BASE, double POWER);",
        "float powf (float BASE, float POWER);",
        "long double powl (long double BASE, long double POWER);",
        "_FloatN powfN (_FloatN BASE, _FloatN POWER);",
        "_FloatNx powfNx (_FloatNx BASE, _FloatNx POWER);",
        "double sqrt (double X);",
        "float sqrtf (float X);",
        "long double sqrtl (long double X);",
        "_FloatN sqrtfN (_FloatN X);",
        "_FloatNx sqrtfNx (_FloatNx X);",
        "double cbrt (double X);",
        "float cbrtf (float X);",
        "long double cbrtl (long double X);",
        "_FloatN cbrtfN (_FloatN X);",
        "_FloatNx cbrtfNx (_FloatNx X);",
        "double hypot (double X, double Y);",
        "float hypotf (float X, float Y);",
        "long double hypotl (long double X, long double Y);",
        "_FloatN hypotfN (_FloatN X, _FloatN Y);",
        "_FloatNx hypotfNx (_FloatNx X, _FloatNx Y);",
        "double expm1 (double X);",
        "float expm1f (float X);",
        "long double expm1l (long double X);",
        "_FloatN expm1fN (_FloatN X);",
        "_FloatNx expm1fNx (_FloatNx X);",
        "double log1p (double X);",
        "float log1pf (float X);",
        "long double log1pl (long double X);",
        "_FloatN log1pfN (_FloatN X);",
        "_FloatNx log1pfNx (_FloatNx X);",
        "complex double cexp (complex double Z);",
        "complex float cexpf (complex float Z);",
        "complex long double cexpl (complex long double Z);",
        "complex _FloatN cexpfN (complex _FloatN Z);",
        "complex _FloatNx cexpfNx (complex _FloatNx Z);",
        "complex double clog (complex double Z);",
        "complex float clogf (complex float Z);",
        "complex long double clogl (complex long double Z);",
        "complex _FloatN clogfN (complex _FloatN Z);",
        "complex _FloatNx clogfNx (complex _FloatNx Z);",
        "complex double clog10 (complex double Z);",
        "complex float clog10f (complex float Z);",
        "complex long double clog10l (complex long double Z);",
        "complex _FloatN clog10fN (complex _FloatN Z);",
        "complex _FloatNx clog10fNx (complex _FloatNx Z);",
        "complex double csqrt (complex double Z);",
        "complex float csqrtf (complex float Z);",
        "complex long double csqrtl (complex long double Z);",
        "complex _FloatN csqrtfN (_FloatN Z);",
        "complex _FloatNx csqrtfNx (complex _FloatNx Z);",
        "complex double cpow (complex double BASE, complex double POWER);",
        "complex float cpowf (complex float BASE, complex float POWER);",
        "complex long double cpowl (complex long double BASE, complex long double POWER);",
        "complex _FloatN cpowfN (complex _FloatN BASE, complex _FloatN POWER);",
        "complex _FloatNx cpowfNx (complex _FloatNx BASE, complex _FloatNx POWER);",
        "double sinh (double X);",
        "float sinhf (float X);",
        "long double sinhl (long double X);",
        "_FloatN sinhfN (_FloatN X);",
        "_FloatNx sinhfNx (_FloatNx X);",
        "double cosh (double X);",
        "float coshf (float X);",
        "long double coshl (long double X);",
        "_FloatN coshfN (_FloatN X);",
        "_FloatNx coshfNx (_FloatNx X);",
        "double tanh (double X);",
        "float tanhf (float X);",
        "long double tanhl (long double X);",
        "_FloatN tanhfN (_FloatN X);",
        "_FloatNx tanhfNx (_FloatNx X);",
        "complex double csinh (complex double Z);",
        "complex float csinhf (complex float Z);",
        "complex long double csinhl (complex long double Z);",
        "complex _FloatN csinhfN (complex _FloatN Z);",
        "complex _FloatNx csinhfNx (complex _FloatNx Z);",
        "complex double ccosh (complex double Z);",
        "complex float ccoshf (complex float Z);",
        "complex long double ccoshl (complex long double Z);",
        "complex _FloatN ccoshfN (complex _FloatN Z);",
        "complex _FloatNx ccoshfNx (complex _FloatNx Z);",
        "complex double ctanh (complex double Z);",
        "complex float ctanhf (complex float Z);",
        "complex long double ctanhl (complex long double Z);",
        "complex _FloatN ctanhfN (complex _FloatN Z);",
        "complex _FloatNx ctanhfNx (complex _FloatNx Z);",
        "double asinh (double X);",
        "float asinhf (float X);",
        "long double asinhl (long double X);",
        "_FloatN asinhfN (_FloatN X);",
        "_FloatNx asinhfNx (_FloatNx X);",
        "double acosh (double X);",
        "float acoshf (float X);",
        "long double acoshl (long double X);",
        "_FloatN acoshfN (_FloatN X);",
        "_FloatNx acoshfNx (_FloatNx X);",
        "double atanh (double X);",
        "float atanhf (float X);",
        "long double atanhl (long double X);",
        "_FloatN atanhfN (_FloatN X);",
        "_FloatNx atanhfNx (_FloatNx X);",
        "complex double casinh (complex double Z);",
        "complex float casinhf (complex float Z);",
        "complex long double casinhl (complex long double Z);",
        "complex _FloatN casinhfN (complex _FloatN Z);",
        "complex _FloatNx casinhfNx (complex _FloatNx Z);",
        "complex double cacosh (complex double Z);",
        "complex float cacoshf (complex float Z);",
        "complex long double cacoshl (complex long double Z);",
        "complex _FloatN cacoshfN (complex _FloatN Z);",
        "complex _FloatNx cacoshfNx (complex _FloatNx Z);",
        "complex double catanh (complex double Z);",
        "complex float catanhf (complex float Z);",
        "complex long double catanhl (complex long double Z);",
        "complex _FloatN catanhfN (complex _FloatN Z);",
        "complex _FloatNx catanhfNx (complex _FloatNx Z);",
        "double erf (double X);",
        "float erff (float X);",
        "long double erfl (long double X);",
        "_FloatN erffN (_FloatN X);",
        "_FloatNx erffNx (_FloatNx X);",
        "double erfc (double X);",
        "float erfcf (float X);",
        "long double erfcl (long double X);",
        "_FloatN erfcfN (_FloatN X);",
        "_FloatNx erfcfNx (_FloatNx X);",
        "double lgamma (double X);",
        "float lgammaf (float X);",
        "long double lgammal (long double X);",
        "_FloatN lgammafN (_FloatN X);",
        "_FloatNx lgammafNx (_FloatNx X);",
        "double lgamma_r (double X, int *SIGNP);",
        "float lgammaf_r (float X, int *SIGNP);",
        "long double lgammal_r (long double X, int *SIGNP);",
        "_FloatN lgammafN_r (_FloatN X, int *SIGNP);",
        "_FloatNx lgammafNx_r (_FloatNx X, int *SIGNP);",
        "double gamma (double X);",
        "float gammaf (float X);",
        "long double gammal (long double X);",
        "double tgamma (double X);",
        "float tgammaf (float X);",
        "long double tgammal (long double X);",
        "_FloatN tgammafN (_FloatN X);",
        "_FloatNx tgammafNx (_FloatNx X);",
        "double j0 (double X);",
        "float j0f (float X);",
        "long double j0l (long double X);",
        "_FloatN j0fN (_FloatN X);",
        "_FloatNx j0fNx (_FloatNx X);",
        "double j1 (double X);",
        "float j1f (float X);",
        "long double j1l (long double X);",
        "_FloatN j1fN (_FloatN X);",
        "_FloatNx j1fNx (_FloatNx X);",
        "double jn (int N, double X);",
        "float jnf (int N, float X);",
        "long double jnl (int N, long double X);",
        "_FloatN jnfN (int N, _FloatN X);",
        "_FloatNx jnfNx (int N, _FloatNx X);",
        "double y0 (double X);",
        "float y0f (float X);",
        "long double y0l (long double X);",
        "_FloatN y0fN (_FloatN X);",
        "_FloatNx y0fNx (_FloatNx X);",
        "double y1 (double X);",
        "float y1f (float X);",
        "long double y1l (long double X);",
        "_FloatN y1fN (_FloatN X);",
        "_FloatNx y1fNx (_FloatNx X);",
        "double yn (int N, double X);",
        "float ynf (int N, float X);",
        "long double ynl (int N, long double X);",
        "_FloatN ynfN (int N, _FloatN X);",
        "_FloatNx ynfNx (int N, _FloatNx X);",
        "int rand (void);",
        "void srand (unsigned int SEED);",
        "int rand_r (unsigned int *SEED);",
        "long int random (void);",
        "void srandom (unsigned int SEED);",
        "char * initstate (unsigned int SEED, char *STATE, size_t SIZE);",
        "char * setstate (char *STATE);",
        "int random_r (struct random_data *restrict BUF, int32_t *restrict RESULT);",
        "int srandom_r (unsigned int SEED, struct random_data *BUF);",
        "int initstate_r (unsigned int SEED, char *restrict STATEBUF, size_t STATELEN, struct random_data *restrict BUF);",
        "int setstate_r (char *restrict STATEBUF, struct random_data *restrict BUF);",
        "double drand48 (void);",
        "double erand48 (unsigned short int XSUBI[3]);",
        "long int lrand48 (void);",
        "long int nrand48 (unsigned short int XSUBI[3]);",
        "long int mrand48 (void);",
        "long int jrand48 (unsigned short int XSUBI[3]);",
        "void srand48 (long int SEEDVAL);",
        "unsigned short int * seed48 (unsigned short int SEED16V[3]);",
        "void lcong48 (unsigned short int PARAM[7]);",
        "int drand48_r (struct drand48_data *BUFFER, double *RESULT);",
        "int erand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, double *RESULT);",
        "int lrand48_r (struct drand48_data *BUFFER, long int *RESULT);",
        "int nrand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, long int *RESULT);",
        "int mrand48_r (struct drand48_data *BUFFER, long int *RESULT);",
        "int jrand48_r (unsigned short int XSUBI[3], struct drand48_data *BUFFER, long int *RESULT);",
        "int srand48_r (long int SEEDVAL, struct drand48_data *BUFFER);",
        "int seed48_r (unsigned short int SEED16V[3], struct drand48_data *BUFFER);",
        "int lcong48_r (unsigned short int PARAM[7], struct drand48_data *BUFFER);",
        "div_t div (int NUMERATOR, int DENOMINATOR);",
        "ldiv_t ldiv (long int NUMERATOR, long int DENOMINATOR);",
        "lldiv_t lldiv (long long int NUMERATOR, long long int DENOMINATOR);",
        "imaxdiv_t imaxdiv (intmax_t NUMERATOR, intmax_t DENOMINATOR);",
        "int isinf (double X);",
        "int isinff (float X);",
        "int isinfl (long double X);",
        "int isnan (double X);",
        "int isnanf (float X);",
        "int isnanl (long double X);",
        "int finite (double X);",
        "int finitef (float X);",
        "int finitel (long double X);",
        "int feclearexcept (int EXCEPTS);",
        "int feraiseexcept (int EXCEPTS);",
        "int fesetexcept (int EXCEPTS);",
        "int fetestexcept (int EXCEPTS);",
        "int fegetexceptflag (fexcept_t *FLAGP, int EXCEPTS);",
        "int fesetexceptflag (const fexcept_t *FLAGP, int EXCEPTS);",
        "int fetestexceptflag (const fexcept_t *FLAGP, int EXCEPTS);",
        "int fegetround (void);",
        "int fesetround (int ROUND);",
        "int fegetenv (fenv_t *ENVP);",
        "int feholdexcept (fenv_t *ENVP);",
        "int fesetenv (const fenv_t *ENVP);",
        "int feupdateenv (const fenv_t *ENVP);",
        "int fegetmode (femode_t *MODEP);",
        "int fesetmode (const femode_t *MODEP);",
        "int feenableexcept (int EXCEPTS);",
        "int fedisableexcept (int EXCEPTS);",
        "int fegetexcept (void);",
        "int abs (int NUMBER);",
        "long int labs (long int NUMBER);",
        "long long int llabs (long long int NUMBER);",
        "intmax_t imaxabs (intmax_t NUMBER);",
        "double fabs (double NUMBER);",
        "float fabsf (float NUMBER);",
        "long double fabsl (long double NUMBER);",
        "_FloatN fabsfN (_FloatN NUMBER);",
        "_FloatNx fabsfNx (_FloatNx NUMBER);",
        "double cabs (complex double Z);",
        "float cabsf (complex float Z);",
        "long double cabsl (complex long double Z);",
        "_FloatN cabsfN (complex _FloatN Z);",
        "_FloatNx cabsfNx (complex _FloatNx Z);",
        "double frexp (double VALUE, int *EXPONENT);",
        "float frexpf (float VALUE, int *EXPONENT);",
        "long double frexpl (long double VALUE, int *EXPONENT);",
        "_FloatN frexpfN (_FloatN VALUE, int *EXPONENT);",
        "_FloatNx frexpfNx (_FloatNx VALUE, int *EXPONENT);",
        "double ldexp (double VALUE, int EXPONENT);",
        "float ldexpf (float VALUE, int EXPONENT);",
        "long double ldexpl (long double VALUE, int EXPONENT);",
        "_FloatN ldexpfN (_FloatN VALUE, int EXPONENT);",
        "_FloatNx ldexpfNx (_FloatNx VALUE, int EXPONENT);",
        "double scalb (double VALUE, double EXPONENT);",
        "float scalbf (float VALUE, float EXPONENT);",
        "long double scalbl (long double VALUE, long double EXPONENT);",
        "double scalbn (double X, int N);",
        "float scalbnf (float X, int N);",
        "long double scalbnl (long double X, int N);",
        "_FloatN scalbnfN (_FloatN X, int N);",
        "_FloatNx scalbnfNx (_FloatNx X, int N);",
        "double scalbln (double X, long int N);",
        "float scalblnf (float X, long int N);",
        "long double scalblnl (long double X, long int N);",
        "_FloatN scalblnfN (_FloatN X, long int N);",
        "_FloatNx scalblnfNx (_FloatNx X, long int N);",
        "double significand (double X);",
        "float significandf (float X);",
        "long double significandl (long double X);",
        "double ceil (double X);",
        "float ceilf (float X);",
        "long double ceill (long double X);",
        "_FloatN ceilfN (_FloatN X);",
        "_FloatNx ceilfNx (_FloatNx X);",
        "double floor (double X);",
        "float floorf (float X);",
        "long double floorl (long double X);",
        "_FloatN floorfN (_FloatN X);",
        "_FloatNx floorfNx (_FloatNx X);",
        "double trunc (double X);",
        "float truncf (float X);",
        "long double truncl (long double X);",
        "_FloatN truncfN (_FloatN X);",
        "_FloatNx truncfNx (_FloatNx X);",
        "double rint (double X);",
        "float rintf (float X);",
        "long double rintl (long double X);",
        "_FloatN rintfN (_FloatN X);",
        "_FloatNx rintfNx (_FloatNx X);",
        "double nearbyint (double X);",
        "float nearbyintf (float X);",
        "long double nearbyintl (long double X);",
        "_FloatN nearbyintfN (_FloatN X);",
        "_FloatNx nearbyintfNx (_FloatNx X);",
        "double round (double X);",
        "float roundf (float X);",
        "long double roundl (long double X);",
        "_FloatN roundfN (_FloatN X);",
        "_FloatNx roundfNx (_FloatNx X);",
        "double roundeven (double X);",
        "float roundevenf (float X);",
        "long double roundevenl (long double X);",
        "_FloatN roundevenfN (_FloatN X);",
        "_FloatNx roundevenfNx (_FloatNx X);",
        "long int lrint (double X);",
        "long int lrintf (float X);",
        "long int lrintl (long double X);",
        "long int lrintfN (_FloatN X);",
        "long int lrintfNx (_FloatNx X);",
        "long long int llrint (double X);",
        "long long int llrintf (float X);",
        "long long int llrintl (long double X);",
        "long long int llrintfN (_FloatN X);",
        "long long int llrintfNx (_FloatNx X);",
        "long int lround (double X);",
        "long int lroundf (float X);",
        "long int lroundl (long double X);",
        "long int lroundfN (_FloatN X);",
        "long int lroundfNx (_FloatNx X);",
        "long long int llround (double X);",
        "long long int llroundf (float X);",
        "long long int llroundl (long double X);",
        "long long int llroundfN (_FloatN X);",
        "long long int llroundfNx (_FloatNx X);",
        "intmax_t fromfp (double X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpf (float X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpl (long double X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpfN (_FloatN X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpfNx (_FloatNx X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfp (double X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpf (float X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpl (long double X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpfN (_FloatN X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpfNx (_FloatNx X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpx (double X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpxf (float X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpxl (long double X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpxfN (_FloatN X, int ROUND, unsigned int WIDTH);",
        "intmax_t fromfpxfNx (_FloatNx X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpx (double X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpxf (float X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpxl (long double X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpxfN (_FloatN X, int ROUND, unsigned int WIDTH);",
        "uintmax_t ufromfpxfNx (_FloatNx X, int ROUND, unsigned int WIDTH);",
        "double modf (double VALUE, double *INTEGER-PART);",
        "float modff (float VALUE, float *INTEGER-PART);",
        "long double modfl (long double VALUE, long double *INTEGER-PART);",
        "_FloatN modffN (_FloatN VALUE, _FloatN *INTEGER-PART);",
        "_FloatNx modffNx (_FloatNx VALUE, _FloatNx *INTEGER-PART);",
        "double fmod (double NUMERATOR, double DENOMINATOR);",
        "float fmodf (float NUMERATOR, float DENOMINATOR);",
        "long double fmodl (long double NUMERATOR, long double DENOMINATOR);",
        "_FloatN fmodfN (_FloatN NUMERATOR, _FloatN DENOMINATOR);",
        "_FloatNx fmodfNx (_FloatNx NUMERATOR, _FloatNx DENOMINATOR);",
        "double remainder (double NUMERATOR, double DENOMINATOR);",
        "float remainderf (float NUMERATOR, float DENOMINATOR);",
        "long double remainderl (long double NUMERATOR, long double DENOMINATOR);",
        "_FloatN remainderfN (_FloatN NUMERATOR, _FloatN DENOMINATOR);",
        "_FloatNx remainderfNx (_FloatNx NUMERATOR, _FloatNx DENOMINATOR);",
        "double drem (double NUMERATOR, double DENOMINATOR);",
        "float dremf (float NUMERATOR, float DENOMINATOR);",
        "long double dreml (long double NUMERATOR, long double DENOMINATOR);",
        "double copysign (double X, double Y);",
        "float copysignf (float X, float Y);",
        "long double copysignl (long double X, long double Y);",
        "_FloatN copysignfN (_FloatN X, _FloatN Y);",
        "_FloatNx copysignfNx (_FloatNx X, _FloatNx Y);",
        "int signbit (_float-type_ X);",
        "double nextafter (double X, double Y);",
        "float nextafterf (float X, float Y);",
        "long double nextafterl (long double X, long double Y);",
        "_FloatN nextafterfN (_FloatN X, _FloatN Y);",
        "_FloatNx nextafterfNx (_FloatNx X, _FloatNx Y);",
        "double nexttoward (double X, long double Y);",
        "float nexttowardf (float X, long double Y);",
        "long double nexttowardl (long double X, long double Y);",
        "double nextup (double X);",
        "float nextupf (float X);",
        "long double nextupl (long double X);",
        "_FloatN nextupfN (_FloatN X);",
        "_FloatNx nextupfNx (_FloatNx X);",
        "double nextdown (double X);",
        "float nextdownf (float X);",
        "long double nextdownl (long double X);",
        "_FloatN nextdownfN (_FloatN X);",
        "_FloatNx nextdownfNx (_FloatNx X);",
        "double nan (const char *TAGP);",
        "float nanf (const char *TAGP);",
        "long double nanl (const char *TAGP);",
        "_FloatN nanfN (const char *TAGP);",
        "_FloatNx nanfNx (const char *TAGP);",
        "int canonicalize (double *CX, const double *X);",
        "int canonicalizef (float *CX, const float *X);",
        "int canonicalizel (long double *CX, const long double *X);",
        "int canonicalizefN (_FloatN *CX, const _FloatN *X);",
        "int canonicalizefNx (_FloatNx *CX, const _FloatNx *X);",
        "double getpayload (const double *X);",
        "float getpayloadf (const float *X);",
        "long double getpayloadl (const long double *X);",
        "_FloatN getpayloadfN (const _FloatN *X);",
        "_FloatNx getpayloadfNx (const _FloatNx *X);",
        "int setpayload (double *X, double PAYLOAD);",
        "int setpayloadf (float *X, float PAYLOAD);",
        "int setpayloadl (long double *X, long double PAYLOAD);",
        "int setpayloadfN (_FloatN *X, _FloatN PAYLOAD);",
        "int setpayloadfNx (_FloatNx *X, _FloatNx PAYLOAD);",
        "int setpayloadsig (double *X, double PAYLOAD);",
        "int setpayloadsigf (float *X, float PAYLOAD);",
        "int setpayloadsigl (long double *X, long double PAYLOAD);",
        "int setpayloadsigfN (_FloatN *X, _FloatN PAYLOAD);",
        "int setpayloadsigfNx (_FloatNx *X, _FloatNx PAYLOAD);",
        "int totalorder (double X, double Y);",
        "int totalorderf (float X, float Y);",
        "int totalorderl (long double X, long double Y);",
        "int totalorderfN (_FloatN X, _FloatN Y);",
        "int totalorderfNx (_FloatNx X, _FloatNx Y);",
        "int totalordermag (double X, double Y);",
        "int totalordermagf (float X, float Y);",
        "int totalordermagl (long double X, long double Y);",
        "int totalordermagfN (_FloatN X, _FloatN Y);",
        "int totalordermagfNx (_FloatNx X, _FloatNx Y);",
        "double fmin (double X, double Y);",
        "float fminf (float X, float Y);",
        "long double fminl (long double X, long double Y);",
        "_FloatN fminfN (_FloatN X, _FloatN Y);",
        "_FloatNx fminfNx (_FloatNx X, _FloatNx Y);",
        "double fmax (double X, double Y);",
        "float fmaxf (float X, float Y);",
        "long double fmaxl (long double X, long double Y);",
        "_FloatN fmaxfN (_FloatN X, _FloatN Y);",
        "_FloatNx fmaxfNx (_FloatNx X, _FloatNx Y);",
        "double fminmag (double X, double Y);",
        "float fminmagf (float X, float Y);",
        "long double fminmagl (long double X, long double Y);",
        "_FloatN fminmagfN (_FloatN X, _FloatN Y);",
        "_FloatNx fminmagfNx (_FloatNx X, _FloatNx Y);",
        "double fmaxmag (double X, double Y);",
        "float fmaxmagf (float X, float Y);",
        "long double fmaxmagl (long double X, long double Y);",
        "_FloatN fmaxmagfN (_FloatN X, _FloatN Y);",
        "_FloatNx fmaxmagfNx (_FloatNx X, _FloatNx Y);",
        "double fdim (double X, double Y);",
        "float fdimf (float X, float Y);",
        "long double fdiml (long double X, long double Y);",
        "_FloatN fdimfN (_FloatN X, _FloatN Y);",
        "_FloatNx fdimfNx (_FloatNx X, _FloatNx Y);",
        "double fma (double X, double Y, double Z);",
        "float fmaf (float X, float Y, float Z);",
        "long double fmal (long double X, long double Y, long double Z);",
        "_FloatN fmafN (_FloatN X, _FloatN Y, _FloatN Z);",
        "_FloatNx fmafNx (_FloatNx X, _FloatNx Y, _FloatNx Z);",
        "double creal (complex double Z);",
        "float crealf (complex float Z);",
        "long double creall (complex long double Z);",
        "_FloatN crealfN (complex _FloatN Z);",
        "_FloatNx crealfNx (complex _FloatNx Z);",
        "double cimag (complex double Z);",
        "float cimagf (complex float Z);",
        "long double cimagl (complex long double Z);",
        "_FloatN cimagfN (complex _FloatN Z);",
        "_FloatNx cimagfNx (complex _FloatNx Z);",
        "complex double conj (complex double Z);",
        "complex float conjf (complex float Z);",
        "complex long double conjl (complex long double Z);",
        "complex _FloatN conjfN (complex _FloatN Z);",
        "complex _FloatNx conjfNx (complex _FloatNx Z);",
        "double carg (complex double Z);",
        "float cargf (complex float Z);",
        "long double cargl (complex long double Z);",
        "_FloatN cargfN (complex _FloatN Z);",
        "_FloatNx cargfNx (complex _FloatNx Z);",
        "complex double cproj (complex double Z);",
        "complex float cprojf (complex float Z);",
        "complex long double cprojl (complex long double Z);",
        "complex _FloatN cprojfN (complex _FloatN Z);",
        "complex _FloatNx cprojfNx (complex _FloatNx Z);",
        "long int strtol (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "long int wcstol (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "unsigned long int strtoul (const char *retrict STRING, char **restrict TAILPTR, int BASE);",
        "unsigned long int wcstoul (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "long long int strtoll (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "long long int wcstoll (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "long long int strtoq (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "long long int wcstoq (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "unsigned long long int strtoull (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "unsigned long long int wcstoull (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "unsigned long long int strtouq (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "unsigned long long int wcstouq (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "intmax_t strtoimax (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "intmax_t wcstoimax (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "uintmax_t strtoumax (const char *restrict STRING, char **restrict TAILPTR, int BASE);",
        "uintmax_t wcstoumax (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR, int BASE);",
        "long int atol (const char *STRING);",
        "int atoi (const char *STRING);",
        "long long int atoll (const char *STRING);",
        "double strtod (const char *restrict STRING, char **restrict TAILPTR);",
        "float strtof (const char *STRING, char **TAILPTR);",
        "long double strtold (const char *STRING, char **TAILPTR);",
        "_FloatN strtofN (const char *STRING, char **TAILPTR);",
        "_FloatNx strtofNx (const char *STRING, char **TAILPTR);",
        "double wcstod (const wchar_t *restrict STRING, wchar_t **restrict TAILPTR);",
        "float wcstof (const wchar_t *STRING, wchar_t **TAILPTR);",
        "long double wcstold (const wchar_t *STRING, wchar_t **TAILPTR);",
        "_FloatN wcstofN (const wchar_t *STRING, wchar_t **TAILPTR);",
        "_FloatNx wcstofNx (const wchar_t *STRING, wchar_t **TAILPTR);",
        "double atof (const char *STRING);",
        "int strfromd (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, double VALUE);",
        "int strfromf (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, float VALUE);",
        "int strfroml (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, long double VALUE);",
        "int strfromfN (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, _FloatN VALUE);",
        "int strfromfNx (char *restrict STRING, size_t SIZE, const char *restrict FORMAT, _FloatNx VALUE);",
        "char * ecvt (double VALUE, int NDIGIT, int *DECPT, int *NEG);",
        "char * fcvt (double VALUE, int NDIGIT, int *DECPT, int *NEG);",
        "char * gcvt (double VALUE, int NDIGIT, char *BUF);",
        "char * qecvt (long double VALUE, int NDIGIT, int *DECPT, int *NEG);",
        "char * qfcvt (long double VALUE, int NDIGIT, int *DECPT, int *NEG);",
        "char * qgcvt (long double VALUE, int NDIGIT, char *BUF);",
        "int ecvt_r (double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);",
        "int fcvt_r (double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);",
        "int qecvt_r (long double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);",
        "int qfcvt_r (long double VALUE, int NDIGIT, int *DECPT, int *NEG, char *BUF, size_t LEN);",
        "double difftime (time_t TIME1, time_t TIME0);",
        "clock_t clock (void);",
        "clock_t times (struct tms *BUFFER);",
        "time_t time (time_t *RESULT);",
        "int stime (const time_t *NEWTIME);",
        "int gettimeofday (struct timeval *TP, struct timezone *TZP);",
        "int settimeofday (const struct timeval *TP, const struct timezone *TZP);",
        "int adjtime (const struct timeval *DELTA, struct timeval *OLDDELTA);",
        "int adjtimex (struct timex *TIMEX);",
        "struct tm * localtime (const time_t *TIME);",
        "struct tm * localtime_r (const time_t *TIME, struct tm *RESULTP);",
        "struct tm * gmtime (const time_t *TIME);",
        "struct tm * gmtime_r (const time_t *TIME, struct tm *RESULTP);",
        "time_t mktime (struct tm *BROKENTIME);",
        "time_t timelocal (struct tm *BROKENTIME);",
        "time_t timegm (struct tm *BROKENTIME);",
        "int ntp_gettime (struct ntptimeval *TPTR);",
        "int ntp_adjtime (struct timex *TPTR);",
        "char * asctime (const struct tm *BROKENTIME);",
        "char * asctime_r (const struct tm *BROKENTIME, char *BUFFER);",
        "char * ctime (const time_t *TIME);",
        "char * ctime_r (const time_t *TIME, char *BUFFER);",
        "size_t strftime (char *S, size_t SIZE, const char *TEMPLATE, const struct tm *BROKENTIME);",
        "size_t wcsftime (wchar_t *S, size_t SIZE, const wchar_t *TEMPLATE, const struct tm *BROKENTIME);",
        "char * strptime (const char *S, const char *FMT, struct tm *TP);",
        "struct tm * getdate (const char *STRING);",
        "int getdate_r (const char *STRING, struct tm *TP);",
        "void tzset (void);",
        "int setitimer (int WHICH, const struct itimerval *NEW, struct itimerval *OLD);",
        "int getitimer (int WHICH, struct itimerval *OLD);",
        "unsigned int alarm (unsigned int SECONDS);",
        "unsigned int sleep (unsigned int SECONDS);",
        "int nanosleep (const struct timespec *REQUESTED_TIME, struct timespec *REMAINING);",
        "int getrusage (int PROCESSES, struct rusage *RUSAGE);",
        "int vtimes (struct vtimes *CURRENT, struct vtimes *CHILD);",
        "int getrlimit (int RESOURCE, struct rlimit *RLP);",
        "int getrlimit64 (int RESOURCE, struct rlimit64 *RLP);",
        "int setrlimit (int RESOURCE, const struct rlimit *RLP);",
        "int setrlimit64 (int RESOURCE, const struct rlimit64 *RLP);",
        "long int ulimit (int CMD, ...);",
        "int vlimit (int RESOURCE, int LIMIT);",
        "int sched_setscheduler (pid_t PID, int POLICY, const struct sched_param *PARAM);",
        "int sched_getscheduler (pid_t PID);",
        "int sched_setparam (pid_t PID, const struct sched_param *PARAM);",
        "int sched_getparam (pid_t PID, struct sched_param *PARAM);",
        "int sched_get_priority_min (int POLICY);",
        "int sched_get_priority_max (int POLICY);",
        "int sched_rr_get_interval (pid_t PID, struct timespec *INTERVAL);",
        "int sched_yield (void);",
        "int getpriority (int CLASS, int ID);",
        "int setpriority (int CLASS, int ID, int NICEVAL);",
        "int nice (int INCREMENT);",
        "int sched_getaffinity (pid_t PID, size_t CPUSETSIZE, cpu_set_t *CPUSET);",
        "int sched_setaffinity (pid_t PID, size_t CPUSETSIZE, const cpu_set_t *CPUSET);",
        "int getpagesize (void);",
        "long int get_phys_pages (void);",
        "long int get_avphys_pages (void);",
        "int get_nprocs_conf (void);",
        "int get_nprocs (void);",
        "int getloadavg (double LOADAVG[], int NELEM);",
        "void longjmp (jmp_buf STATE, int VALUE);",
        "int sigsetjmp (sigjmp_buf STATE, int SAVESIGS);",
        "void siglongjmp (sigjmp_buf STATE, int VALUE);",
        "int getcontext (ucontext_t *UCP);",
        "void makecontext (ucontext_t *UCP, void (*FUNC);",
        "int setcontext (const ucontext_t *UCP);",
        "int swapcontext (ucontext_t *restrict OUCP, const ucontext_t *restrict UCP);",
        "char * strsignal (int SIGNUM);",
        "void psignal (int SIGNUM, const char *MESSAGE);",
        "sighandler_t signal (int SIGNUM, sighandler_t ACTION);",
        "sighandler_t sysv_signal (int SIGNUM, sighandler_t ACTION);",
        "sighandler_t ssignal (int SIGNUM, sighandler_t ACTION);",
        "int sigaction (int SIGNUM, const struct sigaction *restrict ACTION, struct sigaction *restrict OLD-ACTION);",
        "int raise (int SIGNUM);",
        "int gsignal (int SIGNUM);",
        "int kill (pid_t PID, int SIGNUM);",
        "int killpg (int PGID, int SIGNUM);",
        "int sigemptyset (sigset_t *SET);",
        "int sigfillset (sigset_t *SET);",
        "int sigaddset (sigset_t *SET, int SIGNUM);",
        "int sigdelset (sigset_t *SET, int SIGNUM);",
        "int sigismember (const sigset_t *SET, int SIGNUM);",
        "int sigprocmask (int HOW, const sigset_t *restrict SET, sigset_t *restrict OLDSET);",
        "int sigpending (sigset_t *SET);",
        "int pause (void);",
        "int sigsuspend (const sigset_t *SET);",
        "int sigaltstack (const stack_t *restrict STACK, stack_t *restrict OLDSTACK);",
        "int sigstack (struct sigstack *STACK, struct sigstack *OLDSTACK);",
        "int siginterrupt (int SIGNUM, int FAILFLAG);",
        "int sigblock (int MASK);",
        "int sigsetmask (int MASK);",
        "int sigpause (int MASK);",
        "int getopt (int ARGC, char *const *ARGV, const char *OPTIONS);",
        "int getopt_long (int ARGC, char *const *ARGV, const char *SHORTOPTS, const struct option *LONGOPTS, int *INDEXPTR);",
        "int getopt_long_only (int ARGC, char *const *ARGV, const char *SHORTOPTS, const struct option *LONGOPTS, int *INDEXPTR);",
        "error_t argp_parse (const struct argp *ARGP, int ARGC, char **ARGV, unsigned FLAGS, int *ARG_INDEX, void *INPUT);",
        "void argp_usage (const struct argp_state *STATE);",
        "void argp_error (const struct argp_state *STATE, const char *FMT, ...);",
        "void argp_failure (const struct argp_state *STATE, int STATUS, int ERRNUM, const char *FMT, ...);",
        "void argp_state_help (const struct argp_state *STATE, FILE *STREAM, unsigned FLAGS);",
        "void argp_help (const struct argp *ARGP, FILE *STREAM, unsigned FLAGS, char *NAME);",
        "int getsubopt (char **OPTIONP, char *const *TOKENS, char **VALUEP);",
        "char * getenv (const char *NAME);",
        "char * secure_getenv (const char *NAME);",
        "int putenv (char *STRING);",
        "int setenv (const char *NAME, const char *VALUE, int REPLACE);",
        "int unsetenv (const char *NAME);",
        "int clearenv (void);",
        "unsigned long int getauxval (unsigned long int TYPE);",
        "long int syscall (long int SYSNO, ...);",
        "void exit (int STATUS);",
        "int atexit (void (*FUNCTION);",
        "int on_exit (void (*FUNCTION);",
        "void abort (void);",
        "void _exit (int STATUS);",
        "void _Exit (int STATUS);",
        "int system (const char *COMMAND);",
        "pid_t getpid (void);",
        "pid_t getppid (void);",
        "pid_t fork (void);",
        "pid_t vfork (void);",
        "int execv (const char *FILENAME, char *const ARGV[]);",
        "int execl (const char *FILENAME, const char *ARG0, ...);",
        "int execve (const char *FILENAME, char *const ARGV[], char *const ENV[]);",
        "int execle (const char *FILENAME, const char *ARG0, ..., char *const ENV[]);",
        "int execvp (const char *FILENAME, char *const ARGV[]);",
        "int execlp (const char *FILENAME, const char *ARG0, ...);",
        "pid_t waitpid (pid_t PID, int *STATUS_PTR, int OPTIONS);",
        "pid_t wait (int *STATUS_PTR);",
        "pid_t wait4 (pid_t PID, int *STATUS_PTR, int OPTIONS, struct rusage *USAGE);",
        "pid_t wait3 (int *STATUS_PTR, int OPTIONS, struct rusage *USAGE);",
        "int semctl (int SEMID, int SEMNUM, int CMD);",
        "int semget (key_t KEY, int NSEMS, int SEMFLG);",
        "int semop (int SEMID, struct sembuf *SOPS, size_t NSOPS);",
        "int semtimedop (int SEMID, struct sembuf *SOPS, size_t NSOPS, const struct timespec *TIMEOUT);",
        "int sem_init (sem_t *SEM, int PSHARED, unsigned int VALUE);",
        "int sem_destroy (sem_t *SEM);",
        "sem_t *sem_open (const char *NAME, int OFLAG, ...);",
        "int sem_close (sem_t *SEM);",
        "int sem_unlink (const char *NAME);",
        "int sem_wait (sem_t *SEM);",
        "int sem_timedwait (sem_t *SEM, const struct timespec *ABSTIME);",
        "int sem_trywait (sem_t *SEM);",
        "int sem_post (sem_t *SEM);",
        "int sem_getvalue (sem_t *SEM, int *SVAL);",
        "char * ctermid (char *STRING);",
        "pid_t setsid (void);",
        "pid_t getsid (pid_t PID);",
        "pid_t getpgrp (void);",
        "int getpgid (pid_t PID);",
        "int setpgid (pid_t PID, pid_t PGID);",
        "int setpgrp (pid_t PID, pid_t PGID);",
        "pid_t tcgetpgrp (int FILEDES);",
        "int tcsetpgrp (int FILEDES, pid_t PGID);",
        "pid_t tcgetsid (int FILDES);",
        "uid_t getuid (void);",
        "gid_t getgid (void);",
        "uid_t geteuid (void);",
        "gid_t getegid (void);",
        "int getgroups (int COUNT, gid_t *GROUPS);",
        "int seteuid (uid_t NEWEUID);",
        "int setuid (uid_t NEWUID);",
        "int setreuid (uid_t RUID, uid_t EUID);",
        "int setegid (gid_t NEWGID);",
        "int setgid (gid_t NEWGID);",
        "int setregid (gid_t RGID, gid_t EGID);",
        "int setgroups (size_t COUNT, const gid_t *GROUPS);",
        "int initgroups (const char *USER, gid_t GROUP);",
        "int getgrouplist (const char *USER, gid_t GROUP, gid_t *GROUPS, int *NGROUPS);",
        "char * getlogin (void);",
        "char * cuserid (char *STRING);",
        "void setutent (void);",
        "struct utmp * getutent (void);",
        "void endutent (void);",
        "struct utmp * getutid (const struct utmp *ID);",
        "struct utmp * getutline (const struct utmp *LINE);",
        "struct utmp * pututline (const struct utmp *UTMP);",
        "int getutent_r (struct utmp *BUFFER, struct utmp **RESULT);",
        "int getutid_r (const struct utmp *ID, struct utmp *BUFFER, struct utmp **RESULT);",
        "int getutline_r (const struct utmp *LINE, struct utmp *BUFFER, struct utmp **RESULT);",
        "int utmpname (const char *FILE);",
        "void updwtmp (const char *WTMP_FILE, const struct utmp *UTMP);",
        "void setutxent (void);",
        "struct utmpx * getutxent (void);",
        "void endutxent (void);",
        "struct utmpx * getutxid (const struct utmpx *ID);",
        "struct utmpx * getutxline (const struct utmpx *LINE);",
        "struct utmpx * pututxline (const struct utmpx *UTMP);",
        "int utmpxname (const char *FILE);",
        "int getutmp (const struct utmpx *UTMPX, struct utmp *UTMP);",
        "int getutmpx (const struct utmp *UTMP, struct utmpx *UTMPX);",
        "int login_tty (int FILEDES);",
        "void login (const struct utmp *ENTRY);",
        "int logout (const char *UT_LINE);",
        "void logwtmp (const char *UT_LINE, const char *UT_NAME, const char *UT_HOST);",
        "struct passwd * getpwuid (uid_t UID);",
        "int getpwuid_r (uid_t UID, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);",
        "struct passwd * getpwnam (const char *NAME);",
        "int getpwnam_r (const char *NAME, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);",
        "struct passwd * fgetpwent (FILE *STREAM);",
        "int fgetpwent_r (FILE *STREAM, struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);",
        "void setpwent (void);",
        "struct passwd * getpwent (void);",
        "int getpwent_r (struct passwd *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct passwd **RESULT);",
        "void endpwent (void);",
        "int putpwent (const struct passwd *P, FILE *STREAM);",
        "struct group * getgrgid (gid_t GID);",
        "int getgrgid_r (gid_t GID, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);",
        "struct group * getgrnam (const char *NAME);",
        "int getgrnam_r (const char *NAME, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);",
        "struct group * fgetgrent (FILE *STREAM);",
        "int fgetgrent_r (FILE *STREAM, struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);",
        "void setgrent (void);",
        "struct group * getgrent (void);",
        "int getgrent_r (struct group *RESULT_BUF, char *BUFFER, size_t BUFLEN, struct group **RESULT);",
        "void endgrent (void);",
        "int setnetgrent (const char *NETGROUP);",
        "int getnetgrent (char **HOSTP, char **USERP, char **DOMAINP);",
        "int getnetgrent_r (char **HOSTP, char **USERP, char **DOMAINP, char *BUFFER, size_t BUFLEN);",
        "void endnetgrent (void);",
        "int innetgr (const char *NETGROUP, const char *HOST, const char *USER, const char *DOMAIN);",
        "int gethostname (char *NAME, size_t SIZE);",
        "int sethostname (const char *NAME, size_t LENGTH);",
        "int getdomainnname (char *NAME, size_t LENGTH);",
        "int setdomainname (const char *NAME, size_t LENGTH);",
        "long int gethostid (void);",
        "int sethostid (long int ID);",
        "int uname (struct utsname *INFO);",
        "int setfsent (void);",
        "void endfsent (void);",
        "struct fstab * getfsent (void);",
        "struct fstab * getfsspec (const char *NAME);",
        "struct fstab * getfsfile (const char *NAME);",
        "FILE * setmntent (const char *FILE, const char *MODE);",
        "int endmntent (FILE *STREAM);",
        "struct mntent * getmntent (FILE *STREAM);",
        "struct mntent * getmntent_r (FILE *STREAM, struct mntent *RESULT, char *BUFFER, int BUFSIZE);",
        "int addmntent (FILE *STREAM, const struct mntent *MNT);",
        "char * hasmntopt (const struct mntent *MNT, const char *OPT);",
        "int mount (const char *SPECIAL_FILE, const char *DIR, const char *FSTYPE, unsigned long int OPTIONS, const void *DATA);",
        "int umount2 (const char *FILE, int FLAGS);",
        "int umount (const char *FILE);",
        "int sysctl (int *NAMES, int NLEN, void *OLDVAL, size_t *OLDLENP, void *NEWVAL, size_t NEWLEN);",
        "long int sysconf (int PARAMETER);",
        "long int pathconf (const char *FILENAME, int PARAMETER);",
        "long int fpathconf (int FILEDES, int PARAMETER);",
        "size_t confstr (int PARAMETER, char *BUF, size_t LEN);",
        "char * getpass (const char *PROMPT);",
        "char * crypt (const char *KEY, const char *SALT);",
        "char * crypt_r (const char *KEY, const char *SALT, struct crypt_data * DATA);",
        "void setkey (const char *KEY);",
        "void encrypt (char *BLOCK, int EDFLAG);",
        "void setkey_r (const char *KEY, struct crypt_data * DATA);",
        "void encrypt_r (char *BLOCK, int EDFLAG, struct crypt_data * DATA);",
        "int ecb_crypt (char *KEY, char *BLOCKS, unsigned int LEN, unsigned int MODE);",
        "int DES_FAILED (int ERR);",
        "int cbc_crypt (char *KEY, char *BLOCKS, unsigned int LEN, unsigned int MODE, char *IVEC);",
        "void des_setparity (char *KEY);",
        "int getentropy (void *BUFFER, size_t LENGTH);",
        "ssize_t getrandom (void *BUFFER, size_t LENGTH, unsigned int FLAGS);",
        "int backtrace (void **BUFFER, int SIZE);",
        "char ** backtrace_symbols (void *const *BUFFER, int SIZE);",
        "void backtrace_symbols_fd (void *const *BUFFER, int SIZE, int FD);",
        "int pthread_key_create (pthread_key_t *KEY, void (*DESTRUCTOR);",
        "int pthread_key_delete (pthread_key_t KEY);",
        "void *pthread_getspecific (pthread_key_t KEY);",
        "int pthread_setspecific (pthread_key_t KEY, const void *VALUE);",
        "int pthread_getattr_default_np (pthread_attr_t *ATTR);",
        "int pthread_setattr_default_np (pthread_attr_t *ATTR);",
        "uint64_t __ppc_get_timebase (void);",
        "uint64_t __ppc_get_timebase_freq (void);",
        "void __ppc_yield (void);",
        "void __ppc_mdoio (void);",
        "void __ppc_mdoom (void);",
        "void __ppc_set_ppr_med (void);",
        "void __ppc_set_ppr_low (void);",
        "void __ppc_set_ppr_med_low (void);",
        "void __ppc_set_ppr_very_low (void);",
        "void __ppc_set_ppr_med_high (void);",
    ]
