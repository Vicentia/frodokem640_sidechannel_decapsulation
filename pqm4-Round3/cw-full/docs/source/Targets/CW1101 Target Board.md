# ChipWhisperer-Nano Target Board

The ChipWhisperer-Nano also integrates a target board in a similar way to the ChipWhisperer-Lite 1 part version.
Like with the Lite/CW303, this board can be detached from the capture side of the board. Unlike the CW303, however, the Nano target board cannot easily be used standalone - to save space, the full 20-pin connector is not broken out. There
are also no pads to solder SMA connectors to for power analysis/glitching.

![](Images/CWNANO_RESIZE.png)

## Specifications

|Feature|Notes/Range|
|-------|-----------|
| Target Device | STM32F030F4P6 |
| Target Architecture | Arm Cortex M0 |
| Vcc | 3.3V |
| Programming | STM32F Serial, SWD |
| Availability | ChipWhisperer-Nano |
| Status | Released | 
| Shunt | 27Ω |

## LEDs

There are two active high LEDs on the Nano target board:

| Item  | Connection | Note       |
| ----- | ---------- | ---------- |
| D5 (GRN)  | PA2   | Active high |
| D4 (RED) | PA4   | Active high |


## Notes on Usage

A subset of the normal ChipWhisperer 20-pin connector are available via header pins. See the back
of the board or the schematic for the pinout.

The STM32F030F4P6 has 16kB of flash memory, which is not enough to run MBEDTLS RSA. This microcontroller
is available with larger flash sizes, so if you want to run the RSA glitch attack lab, you'll need to replace
the microcontroller on the board with one of the ones with more flash (32K is sufficient).

SWD debug pins are broken out onto TP1 (SWDIO) and TP2 (SWCLK).

## Schematic

![](Images/nano-target-sch.png)