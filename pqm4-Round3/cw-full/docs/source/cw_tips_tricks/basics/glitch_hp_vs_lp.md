# Should I Use `glitch_hp` or `glitch_lp`?

All ChipWhisperer scopes (except for the CW-Nano) offer a choice of two
different MOSFETs for executing crowbar voltage glitches. Our 
[Jupyter course notebooks](https://github.com/newaetech/chipwhisperer-jupyter/blob/main/courses/fault101/)
mention their existence and suggests which to use for different targets but
doesn't explain the choices.

When doing voltage glitching, you can use one or both of `glitch_hp` and
`glitch_lp`, so you have a total of three options. 

In general, `glitch_lp` provides a faster response (so sharper and narrower
glitches are possible) while `glitch_hp` can be better for targets that
require more power. This is discussed in 
[Colin's crowbar paper](https://eprint.iacr.org/2016/810.pdf).

As with glitching in general, there is no one-size-fits-all! It really
depends on your target. Consider the MOSFET choice as just one more
variable, just like all the `scope.glitch` parameters.

