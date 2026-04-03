# Which target instruction does this power sample correspond to?

This is a question which comes up periodically on the forum. While we
can provide some tips for answering that question, let's note right at the
outset that this is often a (somewhat) misguided question.

If you look at our collection of notebooks with this question in mind,
you'll notice that *none* of the attacks demonstrated require knowing which
precise target instruction corresponds to which power sample. For example,
most of the AES attacks that we demonstrate target the S-box of the first
round of AES; in our notebooks we discuss where that round is located in the
power trace, but there is no need to isolate which instructions correspond
to the S-box. Instead, the attacks are carried out over a large segment of
the AES operation which includes the first round of AES.

Some of our ECC notebooks
([sca204](https://github.com/newaetech/chipwhisperer-jupyter/tree/main/courses/sca204),
[sca205](https://github.com/newaetech/chipwhisperer-jupyter/tree/main/courses/sca205))
exploit leakage on very specific power samples, and while there is some
discussion of which instructions are responsible for the leakage, what's
important for the attacks is finding the leakage (not finding the
instructions).

For all of these AES and ECC examples, there is a need for finding the
general area where there is exploitable leakage. This sounds similar to the
question posed in the title, but it's actually a quite different question. In
real-life targets, finding the first round of an AES operation can actually
be very difficult! Often it is also necessary to re-align traces because the
power samples that you wish to target vary in time from trace to trace.


Back to the specific question that's posed in the title: in our notebooks,
most captures are triggered when the target raises `TIO4` via
`trigger_high()`. So a simple thing you can do to learn (loosely) which
instructions corresponds to which section of the power trace is move the
`trigger_high()` call and observe the effect.

Another thing you can do is insert `NOP` operations in the code (or any
operation which you expect to have a distinct signature that can be easily
observed in a power trace).

If you have an Arm target and a CW-Husky (or PhyWhisperer),
[TraceWhisperer](https://github.com/newaetech/tracewhisperer) can be a
useful tool here (but, mind the
[jitter](https://github.com/newaetech/DesignStartTrace?tab=readme-ov-file#trace-jitter)!).

Even with these methods, answering the question accurately will require a
very good understanding of your particular target's micro-architecture,
including its execution pipeline. And unless you have access to your target
microprocessor's gate-level netlist[^1], you'll probably still have to make
some guesses.


[^1]: Which you might! For example, you can an open-source soft-core RISC-V
  processor on an FPGA target board, such as the [lowRISC Ibex core that we
  support](ibex).


