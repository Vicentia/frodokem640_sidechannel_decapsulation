# CW508 SMA Analog Filters

The CW508 Analog Filters provide an easily method of filtering out noise
at both low and high frequency. These two filters serve different
purposes:

  - The high pass filter helps filter out low frequency noise. A common
    cause of this is switch-mode power supplies, which typically operate
    at 50 - 500 kHz.

  - The low pass filter helps remove short spikes from the traces. For
    example, if other peripherals are running on the target, a LPF might
    help remove their effects from the traces. This is especially
    helpful for fast hardware crypto with the slow, synchronous captures
    on the ChipWhisperer. It can be difficult to fix the traces
    afterwards with a digital filter, so it is much more helpful to use
    a hardware filter instead.

These filters can simply be screwed onto the front of the ChipWhisperer
capture device:

![cw508\_cwpro.jpg](Images/Cw508_cwpro.jpg "cw508_cwpro.jpg")

---

## HPF 500 KHz Response

![500khzhpf\_50khz\_5mhz.png](Images/500khzhpf_50khz_5mhz.png
"500khzhpf_50khz_5mhz.png")

![500khzhpf\_50khz\_100mhz.png](Images/500khzhpf_50khz_100mhz.png
"500khzhpf_50khz_100mhz.png")

---

## LPF 20 MHz Response

![20mhzlpf\_100khz\_100mhz.png](Images/20mhzlpf_100khz_100mhz.png
"20mhzlpf_100khz_100mhz.png")
