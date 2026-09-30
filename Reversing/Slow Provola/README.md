# Slow Provola

**Category:** Reversing

## Overview

```text
  sleep(0x1B39u);
  sprintf(v139, "%c%d", (unsigned int)a1[1], 6969);
  v3 = strlen(v139);
  shaprovola(v139, v3, v140);
  for ( j = 0; j <= 31; ++j )
  {
    if ( v140[j] != byte_7080[j] )
    {
      v70 = 0;
      break;
    }
  }
```
This challenge is similar to `Provola`: we have the same main structure, a `check_password` function and the `shaprovola`.
The code above is a snippet of the `check_password` function; there are 68 parts like this.

## Analysis

The code snippet takes the input string `a1`, creates a new string by appending a number to `a1[i]` where `i` is incremented with each part (there are 68 parts of code like this, so it goes from a1[0] to a1[67]).
Then creates a shaprovola and compares it with an array of bytes in the binary.
v70 can be seen as the comparison result because it is set initially to 1.

So each snippet of this code compares a single character of the input with the one required for the flag.
We can infer that the flag length is 68 characters.



## Vulnerability
Side-channel attack: since the comparison between the characters of the flag and the correct sha is done character by character, we can exploit the hit count on that line to guess the flag.


## Exploitation
Inside the `x.py` script we are using libdebug which is a package that allows to automate debugging.

We iterate on printable characters and for each character position we check which is the correct one.
Once we get a correct character for position `i` we fix that string and we start brute-forcing for position `i+1`.

This operation is done by inserting a breakpoint on the positive branch of the comparison for every of the 68 blocks of code: 
```text
.text:0000000000001A51                 cmp     dl, al
.text:0000000000001A53                 jz      short loc_1A5E
.text:0000000000001A55                 mov     [rbp+var_14D], 0
.text:0000000000001A5C                 jmp     short loc_1A6E
```
This is the assembly code for the comparison with the array of bytes, we have to break at the `jz`, in this case 0x1A53.
So breakpoint `i` corresponds to the check for character `i` of the input.

Differently from `Provola`, in this case the breakpoint's hit count must be equal to the length of the `shaprovola` (32) to have a correct character.


### Note
In the code there is a hijack_syscall function that removes the `clock_nanosleep` calls by substituting them with a `read` of 0 characters.
 

