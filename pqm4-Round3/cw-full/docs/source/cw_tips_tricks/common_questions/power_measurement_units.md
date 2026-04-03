# What are the power measurement units?

Sometimes this question is posed as "what are the units on the Y-axis of
power traces". The answer: there are no units; consider it to be
dimensionless.

While all ChipWhisperer capture hardware measures **power traces**, it does
**not** measure power as in "watts"!

The side-channel attacks that "power traces" are typically used for don't
need accurate, calibrated power measurements: they need traces that show
small **relative differences** in measurements. 

When you connect the "measure" port of ChipWhisperer to your NewAE target
board, you will get measurements of the voltage drop across the shunt
resistor that we've placed on our target boards. The measurement is AC-coupled
(it does not measure DC voltage). Finally, the measurements are not calibrated.
These are all purposefully-made design choices: ChipWhisperer is designed to be
good at collecting what is needed for side-channel attacks; it is not designed
to measure power.

This is also why you can connect the measure port to our 
[CW505 H-Field Probe](../../Tools/CW505%20Planar%20H-Field%20Probe.md), obtain
measurements of the magnetic field, and use these in the same side-channel
attacks (perhaps with more traces to deal with the lower SNR). In both this
case and the shunt resistor case, ChipWhisperer measures something which is
only related to the target's power.

If you really need to measure your target's power consumption, you'll need a
different tool; ChipWhisperer is not the right tool for measuring power.

