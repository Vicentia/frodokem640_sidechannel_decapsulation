# How To Use an Electromagnetic Probe

AKA EM probe, H-field probe, RF probe...

All of our target boards are all designed to allow you to obtain power
traces from a shunt resistor. On some other targets, this is not possible;
one solution is to instead measure the electromagnetic field using a probe
such as our [CW505 H-Field Probe](../../Tools/CW505%20Planar%20H-Field%20Probe.md).

Whether you're using our probe or a third-party probe, start by reviewing
the CW505 page linked above. It includes a video that provides hints for
positioning the probe. The quality (SNR) of the traces you'll get is highly
depending on probe placement; this is the tricky part of using these probes.
Some trial-and-error (and patience) is required.

The video uses the old ChipWhisperer GUI (which is [no longer
supported](where_is_the_gui.md)) but the principles are the same. For modern
ChipWhisperer installations, we have a new 
[demo notebook](https://github.com/newaetech/chipwhisperer-jupyter/blob/main/demos/H-Field%20Probe%20Demo%201%20(with%20CPA).ipynb).


