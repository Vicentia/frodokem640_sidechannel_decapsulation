# CANoodler

CANoodler is a simple CAN (not CAN-FD) interface, which provides logic-level 3.3V output. It's designed to be used with microcontrollers that have CAN blocks inside them, and in particular uses a pinout on some ChipWhisperer CW308 (UFO) Target boards.

![](Images/CANoodler.jpg)

## Product Features

* LEDs for TX/RX (driven by MOSFETs to minimize impact on TX/RX lines)
* Reverse-polarity protection on 3.3V input
* Switch for CAN termination on/off with LED feedback
* Requires only a single 3.3V supply
* Two selectable DB9 CAN pinouts via solder jumper

## Usage

CANoodler is simple to use. Simply:

1. Connect the RX pin to your microcontroller CAN-RX pin (this is an OUTPUT from the CANoodler).
1. Connect the TX pin to your microcontroller CAN-TX pin (this is an INPUT to the CANoodler).
1. Provide 3.3V power to the board.
1. Select if you'd like the termination resistor ON or OFF with the switch.
1. Write an entire CAN stack for your microcontroller from scratch, along with a test framework to ensure you meet applicable relevant standards.

### Solder Jumpers

The solder jumpers specify which pinout you'd like on the male DB9 connector.

The default pinout is selected by shorting the LOWER and MIDDLE solder jumpers. It is used by many boards and the Peak CAN USB interface:

* CAN-Low = Pin 2
* CAN-High = Pin 7
* CAN-GND = Pin 3

The "option" pinout is set by moving each of the three solder jumpers to short the UPPER and MIDDLE pads. This pinout is used by cheap ODB-II to DB9 connectors:

* CAN-Low = Pin 5
* CAN-High = Pin 3
* CAN-GND = Pin 2

## Schematic

![](Images/CANoodler-sch.png)