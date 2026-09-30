# crackme

The challenge takes as first argument a string and does some checks to verify if it is equal to the flag.

For the best decompiled version, it is better to use Ghidra.

We can reverse the check function (called catch_function) that just performs the xor between the flag and some byte data.