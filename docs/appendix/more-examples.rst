CTF Challenge Examples
======================

angr is very often used in CTFs. These are example scripts resulting from that
use, mostly from Shellphish but also from many others.

ReverseMe example: HackCon 2016 - angry-reverser
------------------------------------------------

Script author: Stanislas Lejay (github: `@P1kachu
<https://github.com/P1kachu>`_\ )

Script runtime: ~31 minutes

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/yolomolo>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/solve.py>`_

ReverseMe example: SecurityFest 2016 - fairlight
------------------------------------------------

Script author: chuckleberryfinn (github: `@chuckleberryfinn
<https://github.com/chuckleberryfinn>`_\ )

Script runtime: ~20 seconds

A simple reverse me that takes a key as a command line argument and checks it
against 14 checks. Possible to solve the challenge using angr without reversing
any of the checks.

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/fairlight>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/solve.py>`_

ReverseMe example: DEFCON Quals 2016 - baby-re
----------------------------------------------


Authors David Manouchehri (github: `@Manouchehri <https://github.com/Manouchehri>`_\ ),
Stanislas Lejay (github: `@P1kachu <https://github.com/P1kachu>`_\ ) and Audrey Dutcher (github: @rhelmot).

Script runtime: 10 sec

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/baby-re>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/solve.py>`_

ReverseMe example: Google CTF - Unbreakable Enterprise Product Activation (150 points)
--------------------------------------------------------------------------------------

Script 0 author: David Manouchehri (github: `@Manouchehri <https://github.com/Manouchehri>`_\ )

Script runtime: 4.5 sec

Script 1 author: Adam Van Prooyen (github: `@docileninja <https://github.com/docileninja>`_\ )

Script runtime: 6.7 sec

A Linux binary that takes a key as a command line argument and checks it against
a series of constraints.

Challenge Description:

..

   We need help activating this product -- we've lost our license key :(

   You're our only hope!


Here are the binary and scripts: `script 0
<https://github.com/angr/angr-examples/tree/master/examples/google2016_unbreakable_0>`_\
, `script_1
<https://github.com/angr/angr-examples/tree/master/examples/google2016_unbreakable_1>`_

ReverseMe example: EKOPARTY CTF - Fuckzing reverse (250 points)
---------------------------------------------------------------

Author: Adam Van Prooyen (github: `@docileninja <https://github.com/docileninja>`_\ )

Script runtime: 29 sec

A Linux binary that takes a team name as input and checks it against a series of
constraints.

Challenge Description:

..

   Hundreds of conditions to be meet, will you be able to surpass them?


Both sample binaries and the script are located `here
<https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2016_rev250>`_
and additional information be found at the author's `write-up
<http://van.prooyen.com/reversing/2016/10/30/Fuckzing-reverse-Writeup.html>`_.

ReverseMe example: WhiteHat Grant Prix Global Challenge 2015 - Re400
--------------------------------------------------------------------

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

A Windows binary that takes a flag as argument, and tells you if the flag is
correct or not.

"I have to patch out some checks that are difficult for angr to solve (e.g., it
uses some bytes of the flag to decrypt some data, and see if those data are
legit Windows APIs). Other than that, angr works really well for solving this
challenge."

The `binary
<https://github.com/angr/angr-examples/tree/master/examples/whitehatvn2015_re400/re400.exe>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/whitehatvn2015_re400/solve.py>`_.

ReverseMe example: EKOPARTY CTF 2015 - rev 100
----------------------------------------------

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

This is a painful challenge to solve with angr. I should have done things in a
smarter way.

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2015_rev100/counter>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2015_rev100/solve.py>`_.

ReverseMe example: ASIS CTF Finals 2015 - fake
----------------------------------------------

Author: Fish Wang (github: @ltfish)

Script runtime: 1 min 57 sec

The solution is pretty straight-forward.

The `binary
<https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_fake/fake>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_fake/solve.py>`_.

ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 100
-----------------------------------------------------------------

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference.

See the `script
<https://github.com/angr/angr-examples/tree/master/examples/defcamp_r100/solve.py>`_
and the `binary
<https://github.com/angr/angr-examples/tree/master/examples/defcamp_r100/r100>`_.

ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 200
-----------------------------------------------------------------

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference. Veritesting is
required to retrieve the flag promptly.

The `script
<https://github.com/angr/angr-examples/tree/master/examples/defcamp_r200/solve.py>`_
and the `binary
<https://github.com/angr/angr-examples/tree/master/examples/defcamp_r200/r200>`_. It
takes a few minutes to run on my laptop.

ReverseMe example: MMA CTF 2015 - HowToUse
------------------------------------------

Author: Audrey Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to
reverse it or run it in Windows. The resulting `script
<https://github.com/angr/angr-examples/tree/master/examples/mma_howtouse/solve.py>`_
shows how we grabbed the flag out of the `DLL
<https://github.com/angr/angr-examples/tree/master/examples/mma_howtouse/howtouse.dll>`_.

CrackMe example: MMA CTF 2015 - SimpleHash
------------------------------------------

Author: Chris Salls (github: @salls)

This crackme is 95% solvable with angr, but we did have to overcome some
difficulties. The `script
<https://github.com/angr/angr-examples/tree/master/examples/mma_simplehash/solve.py>`_
describes the difficulties that were encountered and how we worked around them.
The binary can be found `here
<https://github.com/angr/angr-examples/tree/master/examples/mma_simplehash/simple_hash>`_.

ReverseMe example: FlareOn 2015 - Challenge 10
----------------------------------------------

Author: Fish Wang (github: @ltfish)

angr acts as a binary loader and an emulator in solving this challenge. I didn't
have to load the driver onto my Windows box.

The `script
<https://github.com/angr/angr-examples/tree/master/examples/flareon2015_10/solve.py>`_
demonstrates how to hook at arbitrary program points without affecting the
intended bytes to be executed (a zero-length hook). It also shows how to read
bytes out of memory and decode as a string.

By the way, here is the `link
<https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf>`_
to the intended solution from FireEye.

ReverseMe example: FlareOn 2015 - Challenge 2
---------------------------------------------

Author: Chris Salls (github: @salls)

This `reversing challenge
<https://github.com/angr/angr-examples/tree/master/examples/flareon2015_2/very_success>`_
is simple to solve almost entirely with angr, and a lot faster than trying to
reverse the password checking function. The script is `here
<https://github.com/angr/angr-examples/tree/master/examples/flareon2015_2/solve.py>`_

ReverseMe example: 0ctf 2016 - momo
-----------------------------------

Author: Fish Wang (github: @ltfish), ocean (github: @ocean1)

This challenge is a `movfuscated <https://github.com/xoreaxeaxeax/movfuscator>`_
binary. To find the correct password after exploring the binary with Qira it is
possible to understand how to find the places in the binary where every
character is checked using capstone and using angr to load the `binary
<https://github.com/angr/angr-examples/tree/master/examples/0ctf_momo_3/solve.py>`_
and brute-force the single characters of the flag. Be aware that the `script
<https://github.com/angr/angr-examples/tree/master/examples/0ctf_momo_3/solve.py>`_
is really slow. Runtime: > 1 hour.

CrackMe example: 9447 CTF 2015 - Reversing 330, "nobranch"
----------------------------------------------------------

Author: Audrey Dutcher (github: @rhelmot)

angr cannot currently solve this problem natively, as the problem is too complex
for z3 to solve. Formatting the constraints to z3 a little differently allows z3
to come up with an answer relatively quickly. (I was asleep while it was
solving, so I don't know exactly how long!) The script for this is `here
<https://github.com/angr/angr-examples/tree/master/examples/9447_nobranch/solve.py>`_
and the binary is `here
<https://github.com/angr/angr-examples/tree/master/examples/9447_nobranch/nobranch>`_.

CrackMe example: ais3_crackme
-----------------------------

Author: Antonio Bianchi, Tyler Nighswander

ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3 summer
school. It is an easy crackme challenge, checking its command line argument.

ReverseMe: Modern Binary Exploitation - CSCI 4968
-------------------------------------------------

Author: David Manouchehri (GitHub `@Manouchehri <https://github.com/Manouchehri>`_\ )

`This folder
<https://github.com/angr/angr-examples/tree/master/examples/CSCI-4968-MBE/challenges>`_
contains scripts used to solve some of the challenges with angr. At the moment
it only contains the examples from the IOLI crackme suite, but eventually other
solutions will be added.

CrackMe example: Android License Check
--------------------------------------

Author: Bernhard Mueller (GitHub `@b-mueller
<https://github.com/angr/angr-examples/tree/master/examples/>`_\ )

A `native binary for Android/ARM
<https://github.com/angr/angr-examples/tree/master/examples/android_arm_license_validation>`_
that validates a license key passed as a command line argument. It was created
for the symbolic execution tutorial in the `OWASP Mobile Testing Guide
<https://github.com/OWASP/owasp-mstg/>`_.
