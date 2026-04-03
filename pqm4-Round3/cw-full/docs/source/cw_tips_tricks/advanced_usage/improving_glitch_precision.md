# Improving Glitch Precision

If you're using a target with its own clock source, it's possible to set up the glitch module to have a higher resolution. The steps to do this are:

* Set the CLKGEN input source to `EXTCLK`.
* Set up the multiply and divide values to make CLKGEN faster than the external clock (for example, Multiply = 10 and Divide = 1). Keep in mind that extremely high clock speeds won't work.
* Set the glitch module's clock source to CLKGEN.

Now, one period of the glitch module's output will be a fraction of the target's clock period. 

This overclocked glitch module is best used with the `Enable Only` output mode, which generates a single pulse that can last for many clock cycles. The `Ext Trigger Offset` and `Repeat` values are in terms of the glitch module's clock, so the pulse's start and end times can be tuned by fractions of a target period.

If the target is using an internal clock source, you can use the ChipWhisperer's internal CLKGEN in a similar way. Though the glitch won't be synchronous with the target's clock, you can still insert extremely precise glitches with this method.
