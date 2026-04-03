# Introduction

This section is a collection of ChipWhisperer tips, tricks, and answers to
common questions. They are mostly things that are not explicitly covered in
our [Jupyter notebooks](https://github.com/newaetech/chipwhisperer-jupyter); 
things you could learn through careful study of the 
[ChipWhisperer scope API](https://chipwhisperer.readthedocs.io/en/latest/scope-api.html), 
but presented here in a way that is easier to find and digest.

Consider it a "greatest hits" of questions we've seen frequently asked on our
[forum](https://forum.newae.com) -- which is where you should head if you
don't find your question answered in these pages.

We've also included some advanced usage tips for things you may not know
that ChipWhisperer can do. Hopefully you find something useful!

Some of the entries are Jupyter notebooks. Unless noted otherwise, these
notebooks run the
[simpleserial-trace](https://github.com/newaetech/chipwhisperer/blob/develop/firmware/mcu/simpleserial-trace/simpleserial-trace-CW308_SAM4S.hex)
firmware on our SAM4S target with CW-Husky. Many of the things taught here are
applicable to different setups, but if you want things to run exactly as they
did for us to generate the outputs you see here, that's what we used.

This site is built with Jupyter Book, which renders notebooks very nicely, so
it may not be immediately obvious which tip & trick entry is a notebook. At
the very top of each page there is a download button; if it shows a `.ipynb`
option, then click on it to download that page's notebook.

If there is no `.ipynb` option, there there is no notebook available.

