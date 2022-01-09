Security
========

angr is meant to be a fully secure environment for analyzing code of any kind in its default configuration. As a result, we take sandbox escapes - opportunities for guest code to manipulate the host environment - very seriously. You _should_ be able to deploy angr in production analyzing untrusted code without worrying about it.

If you find a sandbox escape bug of any sort by this definition, please let us know through a private channel. You can contact the core developers - at time of writing that's @ltfish and @rhelmot - through either their private emails or on the [angr slack server](http://angr.io/invite/).
