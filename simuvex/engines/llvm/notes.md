Value Storage
=============

The built-in LLVM interpreter uses the pointer to a value as the value's identifier.
The LLVM IR printer assigns IDs to instruction results based on positions in the tree.
Though we mostly try to follow the interpreter's design, here we use the second approach, so that value storage can work across different runs of the process (e.g., when pickling a state and using it later).
