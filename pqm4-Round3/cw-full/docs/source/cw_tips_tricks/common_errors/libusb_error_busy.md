# USB Connection Errors

## OSError: Could not find ChipWhisperer. Is it connected?

### Possible Cause #1: ChipWhisperer Not Being Connected

The most likely cause of this error is your ChipWhisperer simply not being connected.

## OSError: Unable to communicate with found ChipWhisperer. Check that another process isn't connected to it and that you have permission to communicate with it.

### Possible Cause #1: Multiple Connections

This error most often occurs when you try to connect to a ChipWhisperer
device that is already connected elsewhere (e.g. in another notebook).

You must disconnect from the first session, either with `scope.dis()` or
by restarting the notebook's kernel, before you can connect to ChipWhisperer
in another notebook.

If you're not sure where your device is connected, typically unplugging + replugging your device fixes this.

### Possible Cause #2: Permission Error

This error can also pop up if our software doesn't have permission to access your hardware
over USB. This happens most commonly on Linux, where you need to give your user
permission to access generic LibUSB devices like ChipWhisperer.

To fix this, try running through our :ref:`Linux installation instructions <linux-install-chipwhisperer>` again.

### Possible Cause #3: Device Crash

It's also possible for this error to occur if Husky has gotten into an
unexpected state that it can't recover from (failed stream captures can
sometimes do this). In this case, a hard reset resolves the problem.

This applies to all ChipWhisperer hardware and software.