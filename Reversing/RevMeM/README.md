# RevMeM
This challenge can be solved in multiple ways, for example:
1. use a debugger to break before the `strcmp` function to see the parameters passed and so get the flag.
I used IDA to get the offset of the `strcmp` function (because PIE was enabled)
and used a `brva 0x122D` on the address with pwndbg.


2. reverse the function as in `x.py`