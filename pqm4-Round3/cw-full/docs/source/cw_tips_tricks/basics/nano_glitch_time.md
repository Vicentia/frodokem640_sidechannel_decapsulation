# Finding Nano Glitch in ADC Data

**Supported Capture Hardware:**\
❌ 
✅ CW-Nano\
❌ CW-Lite\
❌ CW-Pro\
❌ CW-Husky

**Required ChipWhisperer software installation:**\
✅ any release

ChipWhisperer Capture devices with FPGAs (Lite, Pro, Husky, HuskyPlus) have a fixed relationship between the target clock and the glitch timing. This makes it relatively easy to line up a voltage glitch
with its ADC data.

The Nano, on the other hand, utilizes interrupts on its microcontroller for glitching. As such, it has a much less obvious and stable relationship between glitch timing and ADC data. User DonPiekarz from our Discord
server found the approximate relationship: `glitch_time = 47.3 + scope.glitch.ext_offset / 16`. Note that this only holds for large values (around 300 or higher) for `scope.glitch.ext_offset` and for `scope.adc.clk_freq = 7.5E6`, though
it should scale reasonably, meaning `glitch_time` should be roughly double if using a 15MHz ADC clock.