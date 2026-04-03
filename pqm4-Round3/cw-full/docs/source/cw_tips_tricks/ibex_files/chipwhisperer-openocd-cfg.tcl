# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

interface ftdi
ftdi_vid_pid 0x0403 0x6010
ftdi_channel 1
adapter_khz 500
ftdi_layout_init 0x0038 0x003b
ftdi_layout_signal nTRST -data 0x0010
ftdi_layout_signal nSRST -data 0x0020
transport select jtag

# Configure JTAG chain and the target processor
set _CHIPNAME riscv

# Configure JTAG expected ID
# xc7a35 FPGA:
set _EXPECTED_ID 0x0362D093 
# xc7a100 FPGA:
#set _EXPECTED_ID 0x13631093 

jtag newtap $_CHIPNAME cpu -irlen 6 -expected-id $_EXPECTED_ID -ignore-version
set _TARGETNAME $_CHIPNAME.cpu
target create $_TARGETNAME riscv -chain-position $_TARGETNAME

riscv set_ir idcode 0x09
riscv set_ir dtmcs 0x22
riscv set_ir dmi 0x23

#adapter speed 10000

riscv set_prefer_sba on
gdb_report_data_abort enable
gdb_report_register_access_error enable
gdb_breakpoint_override hard

reset_config none

init
halt
