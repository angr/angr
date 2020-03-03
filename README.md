(My)angr
====

# What?

This is my version of the angr framework. I have made some updates to the framework to use in my research that are unlikely to be merged in the mainstream repository buy I'd like to share with anyone interested. 

# What's New?

Implemented features so-far:

## String Formatters 

The original posix.dumps function returns a stream that looks like:

```python
b'foo\x00\x01\x00\x02\x02\x02\x02\x89\x02\x02\x02\x02\x00\x02\x02\x00\x00\x01m\x08)J\x08\x02\x08\x00\x00)\x19)\x08\x19\x00\x19I\x19\x19J\x06\x00\x8a)\x00\x1a\x00\x00\x02\x02\x00\x04\x89\x89\x89\x89\x89\x89\x89bar\x00\x01\x00\x00\x08\x0e\x19\x89\x08\x08\x02\x00\x00\x89\x0e*\x00I\x89\x89\x89\x89\x89\x89\x19\x89\x08\x08\x89\x89\x02\x89\x89\x89*\x01F\x08\x00\x89\x02\x89\xd2\x89\x01\x00\x00\x00)\x02\x02\x00\x00\x00\x19\x00\x00xpto\x00\x08\x01\x08\x00\x00\x00\x02\x01\x00\x02\x00_\x00\x01\x00\x01\x08\x02\x02\x00\x00\x00\x02\x00\x01\x02\x02"\x01J\x02\x02\x01\x02\x02\x02\x01\x08\x10\x00\x19\x02\x89\x1d\x12\x02\xfd\x00\x10\x02\x02\x00\x02\x00\x00'
'''

Now you can get formatted values if you now the expected output types:

```python
['foo', 'bar', 'xpto']
'''

Just Type:

```python
found.posix.dumps(0, fmt='sss')
'''

## Invoked Function Calls

The original events history displays information about unfiltered events:

```python
found.history.events.hardcopy                                                                                
[<SimActionData __libc_start_main() reg/read>,
 <SimActionData __libc_start_main() reg/read>,
 <SimActionData __libc_start_main() reg/write>,
'''

Now you can get information about specific function call invocations without digging into multiple states details:

```python
found.history.calls.hardcopy                                                                                 
[('strcmp', False, <SAO <BV64 0x7fffffffffeff3a>>, <SAO <BV64 0x4008c7>>),
 ('strlen', True, <SAO <BV64 0x7fffffffffeff3a>>),
 ('strlen', True, <SAO <BV64 0x4008c7>>),
 ('strncmp', True, <SAO <BV64 0x7fffffffffeff3a>>, <SAO <BV64 0x4008c7>>, <SimProcedure strlen (inline)>, <SimProcedure strlen (inline)>)]
'''

## Pretty Printers

You can format the previous list to get a better visualization:

```python
angr.pretty_printers.calls.pretty_print_calls(found.history.calls.hardcopy)                                  
[+] strcmp (<SAO <BV64 0x7fffffffffeff3a>>, <SAO <BV64 0x4008c7>>)
	[+] strlen (<SAO <BV64 0x7fffffffffeff3a>>)
	[+] strlen (<SAO <BV64 0x4008c7>>)
	[+] strncmp (<SAO <BV64 0x7fffffffffeff3a>>, <SAO <BV64 0x4008c7>>, <SimProcedure strlen (inline)>, <SimProcedure strlen (inline)>)
[+] strcmp (<SAO <BV64 0x7fffffffffeff44>>, <SAO <BV64 0x4008cb>>)
	[+] strlen (<SAO <BV64 0x7fffffffffeff44>>)
	[+] strlen (<SAO <BV64 0x4008cb>>)
	[+] strncmp (<SAO <BV64 0x7fffffffffeff44>>, <SAO <BV64 0x4008cb>>, <SimProcedure strlen (inline)>, <SimProcedure strlen (inline)>)
[+] strcmp (<SAO <BV64 0x7fffffffffeff4e>>, <SAO <BV64 0x4008cf>>)
	[+] strlen (<SAO <BV64 0x7fffffffffeff4e>>)
	[+] strlen (<SAO <BV64 0x4008cf>>)
	[+] strncmp (<SAO <BV64 0x7fffffffffeff4e>>, <SAO <BV64 0x4008cf>>, <SimProcedure strlen (inline)>, <SimProcedure strlen (inline)>)
'''
