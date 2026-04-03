# How To Use UART Triggering (on Husky)

**Supported Capture Hardware:**\
❌ CW-Nano\
❌ CW-Lite\
❌ CW-Pro\
✅ CW-Husky

**Required ChipWhisperer software installation:**\
✅ any release *(some features unavailable prior to version 6.0.0)*

An external logic analyzer or oscilloscope is not necessary but can be
extremely useful to debug when triggering is not working.

We teach the basics of triggering on UART in 
[this notebook](https://github.com/newaetech/chipwhisperer-jupyter/blob/main/demos/husky/02%20-%20Husky%20Triggers.ipynb);
start there to learn the basics.

If you're here, it's probably because UART triggering is not working for
you. 

UART triggering is all-or-nothing: it either works or it doesn't. When it
doesn't work, Husky won't tell you why. So it can be super helpful to have
an external oscilloscope or logic analyzer to see what's on the wire vs what
you told Husky to expect.

Lots of things can go wrong. Have you set the following correctly in
`scope.UARTTrigger`?
- baudrate
- data bits
- stop bits
- parity

Also:
- have you set {py:meth}`scope.UARTTrigger.trigger_source
  <chipwhisperer.capture.trace.TraceWhisperer.UARTTrigger.trigger_source>`
  to the correct rule?
- is {py:meth}`scope.trigger.triggers
  <chipwhisperer.capture.scopes.cwhardware.ChipWhispererExtra.TriggerSettings.triggers>`
  set to the correct line?
- have you defined your pattern correctly with
  {py:meth}`scope.UARTTrigger.set_pattern_match
  <chipwhisperer.capture.trace.TraceWhisperer.UARTTrigger.set_pattern_match>`?

See the notebook linked above for examples of how to set all of these.

