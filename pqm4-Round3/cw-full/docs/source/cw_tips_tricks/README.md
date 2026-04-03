# ChipWhisperer Tips and Tricks #

This repository hosts a collection of tips and tricks for ChipWhisperer.

It is a submodule that is used to build the ChipWhisperer documentation site,
hosted on [readthedocs](https://chipwhisperer.readthedocs.io).

The documentation source root is in the [chipwhisperer
repository](https://github.com/newaetech/chipwhisperer/tree/develop/docs);
instructions for building it are located there.

Notebooks in this repository are meant to be run locally by NewAE and then
committed *with their outputs* (this is how we want them to be presented in the
online documentation; the notebooks are *not* run when building the
documentation).

A commit on the head of the main branch here must use the head of the
chipwhisperer develop branch.

Release tags mirroring chipwhisperer release tags should be applied here.

