# Where Is the GUI?

ChipWhisperer software was originally built around a GUI interface. The GUI
looked nice and worked great for showing simple attacks, but it was harder
to write advanced attacks or analyses. 

In 2019, we removed the GUI and migrated all our tutorials, demos, and
course contents to [Jupyter Notebooks](https://github.com/newaetech/chipwhisperer-jupyter/tree/main).
There is a learning curve, but we (and others) have found it to be a
fantastic platform for the type of interactive work that side-channel
attacks require. It's also a great teaching platform: it's much easier to
combine instructions, discussions, and code in a notebook, then it is to say
"click here in the GUI".

The last [release](https://github.com/newaetech/chipwhisperer/releases) to
include the GUI was version 4.0.4, which was released in **2018**. You can
still download it and use it, but **we do not support it**. Be aware that:
- it requires Python 2
- it does not support any hardware released since (like Husky)
- it won't have any of the bugfixes that have happened since its release

Hopefully this is enough to convince you to learn Jupyter notebooks!

