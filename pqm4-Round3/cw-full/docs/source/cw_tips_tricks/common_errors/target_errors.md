# ERROR: "Target did not ack" or "no trigger seen"

These are the two errors that users most often run into (if we go by [forum
questions](https://forum.newae.com/search?q=target%20did%20not%20ack)).

The full error message is something like this:\
`(ChipWhisperer Target ERROR|File SimpleSerial.py:351) Target did not ack`

or:\
`(ChipWhisperer Scope WARNING|File _OpenADCInterface.py:730) Timeout in OpenADC capture(), no trigger seen! Trigger forced, data is invalid. Status: 13`

(the line numbers will change as the codebase evolves)

While the errors are different, they are both often tied to target communication issues.

Here we go over the most likely causes, and how to resolve them.

These notes apply to all ChipWhisperer hardware and software.


## Possible Cause #1: Mismatched SimpleSerial Protocol Versions

ChipWhisperer target firmware supports two different versions of the
[SimpleSerial protocol](https://chipwhisperer.readthedocs.io/en/latest/simpleserial.html),
and they are not compatible with each other.

The same version must be used to (1) **build the target firmware**, and to
(2) **connect to the target**.

1. In our firmware build system, the version used is specified as a
   command-line argument to the `make` command. So in our Jupyter notebooks,
   you'll see something like the code below. Here, the `SS_VER` variable
   controls which protocol version is used to build the firmware:
```
SS_VER='SS_VER_2_1'
...
%%bash -s "$PLATFORM" "$CRYPTO_TARGET" "$SS_VER"
make PLATFORM=$1 CRYPTO_TARGET=$2 SS_VER=$3 -j

```
2. In our notebooks, connecting to the target is usually done by running
   [`Setup_Generic.ipynb`](https://github.com/newaetech/chipwhisperer-jupyter/blob/main/Setup_Scripts/Setup_Generic.ipynb),
   which also uses the `SS_VER` definition to determine which protocol
   version Python will use to communicate with the target.

If target compilation and target connection are done in the same notebook,
they both use the same `SS_VER` and so there should be no protocol mismatch
problem.


## Possible Cause #2: Incorrect Baud Rate

SimpleSerial communicates over UART; the baud rate defaults to a
(version-dependent) specific value and assumes a specific target clock rate.

If you change the target clock rate, the baud rate needs to be adjusted
accordingly; see 
["How to change the clock frequency of SimpleSerial targets?"](../basics/baud.ipynb)
to learn how.


## Possible Cause #3: Target Needs a Reset

Some targets require a reset after they are programmed, or after their clock
is changed.

[`Setup_Generic.ipynb`](https://github.com/newaetech/chipwhisperer-jupyter/blob/main/Setup_Scripts/Setup_Generic.ipynb)
defines a target-dependent `reset_target()` function; there is also a manual
reset button on our CW308 and CW313 target boards.

Resetting the target should only be required once; if you find yourself
having to reset the target repeatedly, this is indicative of problems with
your firmware.

## Possible Cause #4: Target Not Programmed or Not Running the Expected Firmware

Seems obvious but it's happened to all of us!

## Possible Cause #5: Firmware Problems

If you're implementing your own target firmware, that may well be where the
problem lies. Any number of things can go wrong; these errors indicate that
the target isn't responding as expected. Using a debugger is usually the
best first step towards figuring out why.


