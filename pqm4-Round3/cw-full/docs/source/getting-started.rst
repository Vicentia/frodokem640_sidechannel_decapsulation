.. _getting_started:

########
Overview
########

New to ChipWhisperer? No problem!

This page will give a brief overview of what ChipWhisperer is, where you can
find documentation about different parts of the ChipWhisperer toolchain,
as well as some of the major changes that have recently happened to ChipWhisperer.

.. _getting_started_what-is-chipwhisperer:

**********************
What is ChipWhisperer?
**********************

ChipWhisperer is a complete open source toolchain for learning about
side channel attacks on embedded devices and validating
the side channel resistance of these devices. In particular,
ChipWhisperer focuses on power analysis, which uses information
leaked by a device's power consumption to mount an attack, as well
as voltage and clock glitching attacks, which briefly disrupt
a device's power or clock to cause unintended behaviour (such 
as skipping a password check).

.. _getting_started-links:

**********
Components
**********

In total, ChipWhisperer has four layers of open source components:

.. _getting_started-hardware:

=========
Hardware
=========

ChipWhisperer has scope boards, which are used to mount side channel attacks,
as well as target boards, which function as a device under test (DUT).
Hardware documentation can be found in the "Hardware" section of this site.

Hardware is for the most part open source and design files/schematics
can be found either on the `ChipWhisperer Capture Github repository`_,
or on a `UFO target board repository`_.

.. image:: _images/cwlite_basic.png
  :width: 600

.. _getting_started-firmware:

=========
Firmware
=========

ChipWhisperer also includes open source firmware for both scopes
and targets. 

Scope firmware is written in Verilog (for
the FPGA) and C (USB microcontroller) and can be found in the
`ChipWhisperer Capture Github repository`_, with the exception of Husky which
has its own `ChipWhisperer Husky Github repository`_.

Target firmware is mostly written in C (though we do have
a few FPGA targets with code in Verilog) and can be found 
in the :code:`firmware` directory of
the `ChipWhisperer Github repository`_.

.. _getting_started-software:

=========
Software
=========

ChipWhisperer has an open source Python library for controlling the
capture hardware and communicating with the target. On this site you'll find 
the Python API documentation, organized in four sections:

* :doc:`scope API <scope-api>`
* :doc:`target API <target-api>`
* :doc:`capture API <capture-api>`
* :doc:`analyzer API <analyzer-api>`

The source code for the API is located on the `ChipWhisperer Github repository`_.

For software installation instructions, head over to the :doc:`installation section <installation>`.


.. _getting_started-tutorials:

==========
Tutorials
==========

The best way to learn ChipWhisperer basics is to follow our 
`Jupyter Notebook tutorials and labs <https://github.com/newaetech/chipwhisperer-jupyter>`__.

By going through our notebooks, you will simultaneously
learn (1) the basic mechanics of side-channel and fault attacks, and (2) how
to execute these attacks with ChipWhisperer.

Approach these tutorials like homework assignments: most of them require you
to figure out some things on your own. The more work you put into it, the
more you'll learn. If you are really stuck, some tutorials have a
corresponding "solution" notebook; you can also ask for help on our `NewAE
Forum`_.


.. image:: _images/jupyter_example.png


.. _getting_started-important-links:

************
Useful Links
************

* :doc:`support`
    Running into trouble? Head here to learn how and where to get help.

* `Issue Tracker`_:
    The issue tracker for the GitHub repository. If you have any issues with
    the ChipWhisperer software that you suspect may be bugs, let us know
    there. Also, if you have any suggestions for future improvements this
    is also place to suggest them. All ideas/suggestions, and issues are
    welcome. Enhancements will be considered, and discussed there before
    the decision is made.

* `Online Courses`_:
    NewAE offers paid online courses that go in depth into
    things not covered by the free tutorials, such as 
    different power measurement techniques, as well as how
    to setup non ChipWhisperer hardware for side channel
    attacks.

* `NewAE Website`_:
    The is the website for NewAE Technology Inc. the maintainers of the
    ChipWhisperer software and the creators the of the ChipWhisperer
    platform. Here you can find out about the company, and find links
    to things like the store, and upcoming training sessions.
    Here you can you also find some other the other products NewAE
    Technology Inc. sells like the electromagnetic fault injection platform,
    the ChipSHOUTER.

* `NewAE Store`_:
    Here you can get yours hands on one of those hardware boards used by all
    of the tutorials. NewAE Technology sells hardware to take away the
    frustration of setting up the hardware for side-channel attacks. These
    boards are available at the `NewAE Store`_. Boards are also available
    on `Mouser`_.

.. _Mouser: https://www.mouser.com/Search/Refine?Keyword=newae
.. _UFO target board repository: https://github.com/newaetech/chipwhisperer-target-cw308t
.. _NewAE Store: https://store.newae.com/
.. _Jupyter Notebook: https://jupyter.org/
.. _ChipWhisperer ReadTheDocs: https://chipwhisperer.readthedocs.io
.. _Issue Tracker: https://github.com/newaetech/chipwhisperer/issues
.. _ChipWhisperer Github repository: https://github.com/newaetech/chipwhisperer
.. _ChipWhisperer Capture Github repository: https://github.com/newaetech/chipwhisperer-capture
.. _NewAE Forum: https://forum.newae.com/
.. _NewAE Website: https://newae.com/
.. _ChipWhisperer Jupyter Github repository: https://github.com/newaetech/chipwhisperer-jupyter
.. _readthedocs: https://readthedocs.org
.. _Online Courses: https://learn.chipwhisperer.io
.. _ChipWhisperer Husky Github repository: https://github.com/newaetech/chipwhisperer-husky

