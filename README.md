# A function identifier for cgc


The identifier uses test cases to identify common library functions in CGC binaries.
It prefilters by finding some basic information about stack variables/arguments.
The information of about stack variables can be generally useful in other projects.

```python
# get all the matches
>>> p = angr.Project("tests/i386/identifiable")
>>> idfer = identifier.Identifier(p)
# note that .run() yields results so make sure to iterate through them or call list() etc
>>> for addr, symbol in idfer.run():
>>>     print hex(addr), symbol
0x804a3d0 strncmp
0x804a0f0 strcmp
0x8048e60 memcmp
0x8049f40 strcasecmp
```
