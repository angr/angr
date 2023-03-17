Introduction
============

angr is a multi-architecture binary analysis toolkit, with the capability to
perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static
analyses on binaries. If you'd like to learn how to use it, you're in the right
place!

We've tried to make using angr as pain-free as possible - our goal is to create
a user-friendly binary analysis suite, allowing a user to simply start up
iPython and easily perform intensive binary analyses with a couple of commands.
That being said, binary analysis is complex, which makes angr complex. This
documentation is an attempt to help out with that, providing narrative
explanation and exploration of angr and its design.

Several challenges must be overcome to programmatically analyze a binary. They
are, roughly:

* Loading a binary into the analysis program.
* Translating a binary into an intermediate representation (IR).
* Performing the actual analysis. This could be:

  * A partial or full-program static analysis (i.e., dependency analysis,
    program slicing).
  * A symbolic exploration of the program's state space (i.e., "Can we execute
    it until we find an overflow?").
  * Some combination of the above (i.e., "Let's execute only program slices that
    lead to a memory write, to find an overflow.")

angr has components that meet all of these challenges. This documentation will
explain how each component works, and how they can all be used to accomplish
your goals.

Getting Support
---------------

To get help with angr, you can ask via:


* the slack channel: `angr.slack.com <https://angr.slack.com>`_, for which you
  can get an account `here <https://angr.io/invite/>`_.
* opening an issue on the appropriate github repository

Citing angr
-----------

If you use angr in an academic work, please cite the papers for which it was developed:

.. code-block:: bibtex

   @article{shoshitaishvili2016state,
     title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
     author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, Jessie and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={IEEE Symposium on Security and Privacy},
     year={2016}
   }

   @article{stephens2016driller,
     title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
     author={Stephens, Nick and Grosen, Jessie and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={NDSS},
     year={2016}
   }

   @article{shoshitaishvili2015firmalice,
     title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
     author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={NDSS},
     year={2015}
   }

Going further:
--------------

You can read this `paper
<https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf>`_,
explaining some of the internals, algorithms, and used techniques to get a
better understanding on what's going on under the hood.

If you enjoy playing CTFs and would like to learn angr in a similar fashion,
`angr_ctf <https://github.com/jakespringer/angr_ctf>`_ will be a fun way for you
to get familiar with much of the symbolic execution capability of angr. `The
angr_ctf repo <https://github.com/jakespringer/angr_ctf>`_ is maintained by
`@jakespringer <https://github.com/jakespringer>`_.
