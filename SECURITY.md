Security
========

angr is meant to be able to function as fully secure environment for analyzing code of any kind in its default configuration.
As a result, we take sandbox escapes - opportunities for guest code to manipulate the host environment without the analysis author explicitly allowing it - very seriously.
If you read all the documentation, you should be able to deploy angr to analyze untrusted code without worrying about it.

If you find a sandbox escape bug of any sort by this definition, please let us know through a private channel.
You can contact the core developers through their emails at audrey@rhelmot.io and fishw@asu.edu.
