# How to use an external clock?

In all of our notebooks (except the CW305 notebooks), the ChipWhisperer
capture device generates the target clock.

All ChipWhisperers are able to instead use an externally-generated clock
(e.g. a target-generated clock) to derive their ADC sampling clocks. Exactly
how this is done depends on the device.

If your target is running our SimpleSerial protocol, keep in mind the
relationship between clock rates and baud rate, which is explained
[here](baud.ipynb).

For all ChipWhisperers except the Nano, sometimes changing the ADC clock
source causes the ADC clock to become unlocked (i.e.
`scope.clock.adc_locked` is `False`); calling `scope.clock.reset_adc()` can
fix this.

For the ChipWhisperer Nano, there is no lock indicator; call
`scope.reset_clock_phase()`.


## ChipWhisperer Nano
Provide a clock on the HS1 port of the 20-pin header and set
`scope.adc.clk_src = 'ext'`.


## ChipWhisperer Lite and Pro
Provide a clock on the HS1 port of the 20-pin header.
Set `scope.clock.adc_src` to one of the following options:
- `'extclk_dir'`: the HS1 clock is used directly as the ADC sampling clock.
- `'extclk_x1'`: the HS1 clock is routed to an FPGA DCM (PLL), its
  frequency is left unchanged, and the output of that PLL is used as the ADC
  sampling clock.
- `'extclk_x4'`: the HS1 clock is routed to an FPGA DCM (PLL), which
  multiplies it by 4 to generate the ADC sampling clock.


## ChipWhisperer Husky

Provide a clock on the HS1 port of the 20-pin header (set
`scope.clock.clkgen_src = 'extclk'`),
or on the AUX in/out MCX (set `scope.clock.clkgen_src = 'extclk_aux_io'` and
`scope.io.aux_io_mcx = 'high_z'`)

Set `scope.clock.clkgen_freq` to the frequency of the external clock.

Set `scope.clock.adc_mul` as desired.


