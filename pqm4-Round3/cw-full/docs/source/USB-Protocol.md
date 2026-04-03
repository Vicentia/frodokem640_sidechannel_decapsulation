# ChipWhisperer USB Protocol

[Useful reading](https://www.beyondlogic.org/usbnutshell/usb1.shtml).

## Basic Overview

USB stuff is handled in `usb.c`. `main_setup_out_received()` handles OUT setup packets,
while `main_setup_in_received()` handles IN setup packets. 

Both functions select different commands based on the USB `bRequest` field. OUT packet
commands are handled in a callback, while IN packet commands are handled directly
in `main_setup_in_received()`.

Depending on the command, `wValue` and/or `payload` may be used as command parameters.

If the SAM3U is unable to process the setup packet (aka either `setup_*_received()` returns `false`)
you'll get a pipe error on the Python side.

## ChipWhisperer-Lite

### Setup OUT Commands

#### 0x10: REQ_MEMREAD_BULK


Setup a bulk IN transfer to read from the FPGA. This command must be sent before 
attempting to read from the bulk endpoint. An additional bulk transfer is not
setup upon this one completing, meaning this command must be called again
to do another bulk read.

##### wValue

Unused

##### payload 

* Bytes 0-3: Length of data to read from FPGA
* Bytes 4-7: FPGA Address to read from

</details>

___

#### 0x11: REQ_MEMWRITE_BULK

Setup a bulk OUT transfer to write to the FPGA. This command must be sent
before attempting to write to the bulk endpoint.

##### wValue

Unused

##### payload 

* Bytes 0-3: Unused
* Bytes 4-7: FPGA Address to write to

___

#### 0x12: REQ_MEMREAD_CTRL

Setup a read from the FPGA as a control IN transfer. An IN transfer with this same
`bRequest` will read data off the FPGA once this command has been called.

##### wValue

Unused

##### payload 

* Bytes 0-3: Length of data to read from FPGA
* Bytes 4-7: FPGA Address to read from

___

#### 0x13: REQ_MEMWRITE_CTRL

Write data to the FPGA.

##### wValue

Unused

##### payload 

* Bytes 0-3: Length of data to write to FPGA
* Bytes 4-7: FPGA Address to write to
* Bytes 8+:  Data to write to FPGA

___

#### 0x16: REQ_FPGA_PROGRAM
Setup FPGA bitstream programming

##### wValue

* 0xA0: Step 1 - setup peripherals, erase FPGA
* 0xA1: Step 2 - setup bulk endpoint to write over SPI instead of the external memory interface. You still need to setup via `REQ_MEMWRITE_BULK`
                 before writing data to the bulk endpoint
* 0xA2: Step 3 - set bulk endpoint back to external memory interface (usual FPGA communication). Call once the FPGA has been programmed

##### payload
Unused

___

#### 0x1A: REQ_USART0_DATA

Sends data over the USART interface

##### wValue

Unused

##### payload

Data to send

---

#### 0x1B: REQ_USART0_CONFIG
USART configuration and special commands

##### wValue

Selects the USART command. The following commands
are valid for OUT packets:

* 0x0010: USART port configuration - baud, parity, etc.
* 0x0011: USART port enable
* 0x0012: USART port disable

##### payload

Only valid for `wValue=0x0010` (USART port configuration):

* Bytes 0-3: Baud rate
* Byte  4:   Stop bit selection. 0 sets 1 stop bit, 1 sets 1.5 stop bits, 2 sets 2 stop bits
* Byte  5:   Parity selection:   0 sets no parity, 1 sets odd, 2 sets even, 3 sets mark, 4 sets space
* Byte  6:   Sets data length. Values of 5-8 are valid.

___

#### 0x1C-0x1E: Smart Card Interface

Hasn't been used in a while, may not work

#### 0x1F: USART2 Dump Enable

Seems to be unused

---

#### 0x20: REQ_XMEGA_PROGRAM

Do XMEGA PDI command

##### wValue

Low 8 bits: command to perform

* 0x01: Enter programming mode
* 0x02: Leave programming mode
* 0x03: Erase XMEGA
* 0x04: Write mem
* 0x05: Read mem
* 0x06: CRC (does nothing)
* 0x07: Set param
* 0x22: Write data to internal rambuf

Upper 8 bits: offset for command 0x22

##### payload

See `pdi/XPROGNewAE.c`

___

#### 0x21: REQ_AVR_PROGRAM

TODO

#### 0x22: REQ_SAM3U_CFG

SAM3U configuration and special commands

##### wValue

* 0x01: Turn on slow clock for new AVR programming
* 0x02: Turn off slow clock
* 0x03: Enter bootloader for firmware upgrade
* 0x10: Reset SAM3U (firmware x.30 and later)
* 0x11: Release FPGA lock - can fix some pipe errors cased by interruption of usb communication (firmware x.30 and later)

##### payload

Unused

___

#### 0x31: REQ_CDC_SETTINGS_EN

Allow or disallow CDC interface to change USART settings.

##### wValue

* Bit 0: Allow CDC settings change if 1 or disallow if 0
* Bit 1: Unused, reserved for additional CDC interfaces

##### payload

Unused

___

### Setup IN Commands

#### 0x12: REQ_MEMREAD_CTRL

Does the actual FPGA read setup by the `REQ_MEMREAD_CTRL` OUT command.

##### wValue

Unused

##### payload

Read FPGA data

____

#### 0x15: REQ_FPGA_STATUS

Checks whether or not the FPGA has finished being programmed

##### wValue

Unused

##### payload

Byte 0: 1 if FPGA programmed, 0 otherwise
Bytes 1-3: 0x00


____

#### 0x17: REQ_FW_VERSION

Get the version of the SAM3U firmware

##### wValue

Unused

##### payload

Byte 0: FW_VER_MAJOR
Byte 1: FW_VER_MINOR
Byte 2: FW_VER_MINOR

___

#### 0x1A: REQ_USART0_DATA

Read data from the SAM3U's USART buffer

##### wValue

Unused

##### payload

USART data

____

#### 0x1A: REQ_USART0_CONFIG

Read status of SAM3U USART

##### wValue

* 0x0010: Reserved
* 0x0014: Get number of characters in USART RX buffer (in_waiting)
* 0x0018: Get number of characters in USART TX buffer (tx_in_waiting)

##### payload

For in_waiting commands:

* Bytes 0-3: number of characters in buffer

____

#### 0x20: REQ_XMEGA_PROGRAM

##### wValue

* 0x20: Get status
* 0x21: Read data from internal rambuf

##### payload

Requested Data

____

#### 0x21: REQ_AVR_PROGRAM

TODO

___

#### 0x31: REQ_CDC_SETTINGS_EN

See whether the CDC port is allowed to modify the USART settings

##### wValue

Unused

##### payload

* Byte 0: 1 if CDC Port 0 can change USART settings, otherwise 0
* Byte 1: Reserved for additional CDC Ports

___

## ChipWhisperer-Pro

Uses the same commands as the Lite, but adds a few new commands

### New OUT Commands

#### 0x14: REQ_MEMSTREAM

TODO

##### wValue

Unused

##### payload

* Bytes 0-3: 

____

### New IN Commands

#### 0x14: REQ_MEMSTREAM

TODO

##### wValue

Unused

##### payload

* Bytes 0-3: 

____

## ChipWhisperer-Nano

Shares most commands with the Lite/Pro, but some commands
have different behaviour. Also has a few new commands.

### New/Changed OUT Commands

#### 0x10: REQ_READMEM_BULK

##### wValue

Unused

##### payload

Bytes 0-3: number of bytes to read from ADC, up to a maximum of 100 000

___

#### 0x11: REQ_WRITEMEM_BULK

Does nothing

___

#### 0x12: REQ_READMEM_CTRL

##### wValue

Unused

##### payload

Bytes 0-3: number of bytes to read from ADC, up to a maximum of 100 000 bytes

___

#### 0x13: REQ_WRITEMEM_CTRL

Does nothing

___

#### 0x25: REQ_GPIO_OUT

Configures GPIO pins

##### wValue

Selects GPIO Configuration

* 0x01: Set pin as output
* 0x02: Set pin as input
* 0x03: Set pin high
* 0x04: Set pin low
* 0x05: Set pin as peripheral A
* 0x06: Set pin as peripheral B

##### payload

* Byte 0: Bitmask of pins to update

* GPIO3 = `(1 << 2)`
* GPIOnRST = `(1 << 4)`
* GPIOPDIC = `(1 << 5)`
* GPIOPDID = `(1 << 6)`

___

#### 0x27: REQ_CLK_OUT

Sets clock division for output clock

##### wValue

Unused

##### payload

* Byte 0: The clock divisor. Can be 1 or any multiple of 2 up to 64.

___

#### 0x28: REQ_ADCCLK_OUT

##### wValue

Unused

##### payload

* Byte 0: The clock divisor. Can be 1 or any multiple of 2 up to 64.
* Bytes 1-2: Unused
* Byte 3: ADC clock source. If 0, use internal clock. Otherwise, use external clock
* Byte 4: ADC clock enable. If 0, disable clock. Otherwise, enable clock

___

#### 0x29: REQ_ARM

Arm the scope.

##### wValue

* If 1, arm scope. Otherwise, do nothing

##### payload

Unused

___

#### 0x2A: REQ_SAMPLES

Set the number of samples to capture.

##### wValue

Unused

##### payload

* Bytes 0-3: Number of samples to capture. Should not be set above 100 000.

___

#### 0x2C: REQ_GLITCHSET

Change glitch settings

##### wValue

Unused

##### payload

* Bytes 0-3: Glitch offset
* Bytes 4-7: Glitch width

#### 0x2D: REQ_GLITCHGO

Manually trigger glitch

##### wValue

Unused

##### payload

Unused


____

### New/Changed IN Commands

#### 0x27: REQ_CLK_OUT

##### wValue

Unused

##### payload

* Byte 0: Clock divisor
* Bytes 1-2: 0x00

___

#### 0x28: REQ_ADCCLK_OUT

##### wValue

Unused

##### payload

* Byte 0: Clock divisor
* Bytes 1-2: 0x00
* Byte 3: Clock source
* Byte 4: Clock enabled

___

#### 0x29: REQ_ARM

##### wValue

Unused

##### payload

* Byte 0: 1 if capture done, 0 otherwise

___

#### 0x2A: REQ_SAMPLES

The number of ADC samples the Nano will capture

##### wValue

Unused

##### payload

* Bytes 0-3: Number of samples to capture

___

#### 0x2B: REQ_BUFSIZE

ADC sample buffer size - the maximum number of samples that can be captured.

##### wValue

Unused

##### payload

* Bytes 0-3: ADC sample buffer size

___

#### 0x2C: REQ_GLITCHSET

Read glitch settings

##### wValue

Unused

##### payload

* Bytes 0-3: Glitch offset
* Bytes 4-7: Glitch width

___

### Removed OUT Commands

#### 0x16: REQ_FPGA_PROGRAM

____

### Removed IN Commands

#### 0x15: REQ_FPGA_STATUS

#### 0x21: REQ_AVR_PROGRAM

___

## ChipWhisperer CW305 Artix 

Again, many USB commands are shared between the ChipWhisperer-Lite and CW305.

### New/Changed OUT Commands

#### 0x11: REQ_MEMWRITE_BULK

Setup a bulk OUT transfer to write to the FPGA. This command must be sent
before attempting to write to the bulk endpoint. The address field is unused.

##### wValue

Unused

##### payload 

* Bytes 0-7: Unused

___

#### 0x15: REQ_MEMWRITE_CTRL_SAMU3

TODO: (seeded encryption for super speed)

#### 0x22: REQ_SAM3U_CFG

SAM3U configuration and special commands

##### wValue

* 0x01: Turn on slow clock for new AVR programming
* 0x02: Turn off slow clock
* 0x03: Enter bootloader for firmware upgrade
* 0x04: Turn off FPGA clock
* 0x05: Turn on FPGA clock
* 0x06: Toggle trigger pin

##### payload

Unused

___

#### 0x30: REQ_CDCE906

Do a write to or read from the CW305's CDCE906 PLL chip over I2C. The status of the command can
be read with an IN REQ_CDCE906.

##### wValue

Unused

##### payload

* Byte 0: If 0, do a read. If 1, do a write.
* Byte 1: CDCE906 Address to read/write
* Byte 2: Unused if doing a read. The data to write if doing a write.

____

#### 0x31: REQ_VCCINT

Set the VCCINT voltage for the FPGA chip.

**WARNING: The bounds for this command are 600mV to 1200mV, but the maximum voltage for the FPGA
chip is 1100mV. Exceeding this voltage may damage the FPGA. **

##### wValue

Unused

##### payload

Bytes 0-1: 16-bit integer representing the desired voltage in mV
Byte 2: Checksum. Equal to (`payload[0] ^ payload[1] ^ 0xAE`)

____

#### 0x33: REQ_FPGASPI_PROGRAM

Bit-bang SPI data to the CW305 SPI chip. Assumes the FPGA is already configured
with the pass-through bitstream to route the SAM3U pins to the SPI flash.

##### wValue

Command select:

* 0xA0: Init SPI
* 0xA1: Deinit SPI
* 0xA2: Set CS pin low
* 0xA3: Set CS pin high
* 0xA4: Send data

##### payload

Data to send to the SPI flash. Unused unless
`wValue == 0xA4`.

_____

#### 0x34: REQ_FPGAIO_UTIL

Generic SAM3U pin configuration control

##### wValue

Select operation:

* 0xA0: Configure pin
* 0xA1: Release IO pin
* 0xA2: Set IO pin low or high

##### payload

* Byte 0: Select pin (based on Atmel ASF GPIO numbering)
* Byte 1: `config`

If `wValue == 0xA0`, `config` should be set as follows:

* 0x01: Configure pin as input
* 0x02: Configure pin as output high
* 0x10: Configure pin as SPI MOSI
* 0x11: Configure pin as SPI MISO
* 0x12: Configure pin as SPI SCK
* 0x13: Configure pin as SPI CS

If `wValue == 0xA2`, `config` should be set as follows:

* 0x00: Set pin low
* 0x01: Set pin high

___

#### 0x35: FREQ_FPGASPI1_XFER

Bit-bang SPI. Must configure pins using `REQ_FPGAIO_UTIL` before using this command.

##### wValue

Command select:

* 0xA0: Init SPI
* 0xA1: Deinit SPI
* 0xA2: Set CS pin low
* 0xA3: Set CS pin high
* 0xA4: Send data

##### payload

Data to send. Unused unless
`wValue == 0xA4`.

____

### New/Changed IN Commands

#### 0x30: REQ_CDCE906

Read status/data back from an OUT REQ_CDCE906 command. You should
do a write/read using the OUT version of this command before calling this one

##### wValue

Unused

##### payload

* Byte 0: Status of command
* Byte 1: Received data

____

#### 0x31: REQ_VCCINT

Read what voltage the VCCINT regulator is set to.

##### wValue

Unused

##### payload

* Byte 0: Status
* Byte 1-2: 16-bit integer representing set voltage in mV

___

#### 0x33: REQ_FPGASPI_PROGRAM

Read data back from the FPGASPI buffer.

You should use the OUT version of this command to do the actual transfer.

##### wValue

Unused

##### payload

Data in the FPGASPI buffer

___

#### 0x35: REQ_FPGASPI1_XFER

Read data back from the generic bit-bang SPI buffer.

You should use the OUT version of this command to do the actual transfer.

##### wValue

Unused

##### payload

Data in the SPI buffer
____

### Removed OUT Commands

#### 0x1A: USART0_DATA

#### 0x1B: USART0_CONFIG

#### 0x20: REQ_XMEGA_PROGRAM

#### 0x21: REQ_AVR_PROGRAM

#### 0x31: REQ_CDC_SETTINGS_EN

___

### Removed IN Commands

#### 0x1A: USART0_DATA

#### 0x1B: USART0_CONFIG

#### 0x20: REQ_XMEGA_PROGRAM

#### 0x21: REQ_AVR_PROGRAM

#### 0x31: REQ_CDC_SETTINGS_EN
