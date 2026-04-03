# Can I Get More Samples Per Clock Cycle?

Maybe. But why would you? Before answering we need to talk about synchronous
sampling.

## Synchronous vs Asynchronous Sampling

Before ChipWhisperer, side-channel practitioners usually needed very
expensive oscilloscopes with very high sampling rates to get good/useful
power traces. They needed a high sampling rate because they were sampling
*asynchronously*, which means that there is no relationship between the
target clock and the sampling clock.

One of the defining feature of ChipWhisperer is that it samples
*synchronously*: it uses a PLL to synchronize its ADC sampling clock to the
target clock. This, it turns out, allows side-channel attacks to succeed
with a single sample per clock cycle. All of our 
[Jupyter course notebooks](https://github.com/newaetech/chipwhisperer-jupyter/tree/main/courses)
use either 1 or 4 samples per clock cycle.

If you're not convinced, read Colin's paper which compares synchronous
sampling at these low rates with asynchronous sampling at much higher rates: 
["Synchronous Sampling and Clock Recovery of Internal
Oscillators for Side Channel Analysis and Fault Injection"](https://eprint.iacr.org/2013/294.pdf).
The results are very interesting! Synchronous sampling is shown to
outperform asynchronous sampling at a sampling rate that's nearly two orders
of magnitude higher. This is why we've settled on 1x or 4x sampling.

## But I Still Want a Higher Sampling Rate!

ChipWhisperer Husky has a more powerful and flexible clock scheme: with
Husky you can, if you want, set the number of samples per clock to any
integer (up to the maximum supported sampling rate) with the
{py:meth}`scope.clock.adc_mul <chipwhisperer.capture.scopes._OpenADCInterface.ClockSettings.adc_mul>`
parameter.

This is not possible on the ChipWhisperer-Lite, Pro, or Nano. If you insist
on a achieving a higher sampling rate using one of these, your only option
is to sample asynchronously. Although it's not how ChipWhisperer is not
meant to be used, it **is** possible to configure ChipWhisperer to sample
asynchronously. You'll need to supply your target's clock from elsewhere (it
can't come from ChipWhisperer). If you are using a CW308 target, you can use
its [crystal driver](../../Targets/CW308%20UFO.md#crystal-driver) as the clock
source. Our larger FPGA target boards like the CW305 have 
[on-board PLLs](../../Targets/CW305%20Artix%20FPGA.md#pll) that can generate
an independent target clock. Then, on the ChipWhisperer side, simply set the
ADC clock source to **not** be set from the external (target) clock, e.g.
{py:meth}`scope.clock.adc_src = "clkgen_x1" <chipwhisperer.capture.scopes._OpenADCInterface.ClockSettings.adc_src>`.

To be clear: we don't recommend you do this -- unless you have to.
If you don't have access to the target's clock, and you're unable to drive
the target's clock from ChipWhisperer, then asynchronous sampling is your
only option. In this case you should probably set the sampling rate
as high as your capture hardware allows. Maximum sampling rates as listed
[here](../../Capture/overview.md#analog-capture-and-clock).


