# Provola

**Category:** Reversing

## Overview

```text
__int64 __fastcall check_password(const char *a1)
{
  int i; // [rsp+18h] [rbp-38h]
  int j; // [rsp+1Ch] [rbp-34h]
  _BYTE v4[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( strlen(a1) != 37 )
    return 0;
  for ( i = 0; i <= 36; ++i )
  {
    shaprovola(&a1[i], 1, v4);
    for ( j = 0; j <= 31; ++j )
    {
      if ( v4[j] != provola[32 * i + j] )
        return 0;
    }
  }
  return 1;
}
```
This challenge asks for a secret password (that is the final flag) and does some comparisons to check whether the password is correct or not.
As we can see above, in the `check_password` function, there is a call to `shaprovola` that is computed on each character of the flag, then the sha is compared with an array of bytes.

## Analysis

The `shaprovola` function is too complicated to be reversed and impossible to be symbolically executed with tools like z3 (also because normally a SHA is a one-way function).
By analyzing the code above, we can see that the comparison `if ( v4[j] != provola[32 * i + j] )` is executed for every character in the input.

We can brute force the flag using a so called "side-channel attack": by counting how many times the program executes correctly the comparison line, we can infer how many consecutive characters of the flag are correct.


## Vulnerability
Side-channel attack: since the comparison between the characters of the flag and the correct sha is done character by character, we can exploit the hit count on that line to guess the flag.


## Exploitation
Inside the `x.py` script we are using libdebug which is a package that allows to automate debugging.

We iterate on printable characters and for each character position we check which is the correct one.
Once we get a correct character for position `i` we fix that string and we start brute-forcing for position `i+1`.

This operation is done by inserting a breakpoint on this assembly code `.text:0000000000001A0F                 add     [rbp+var_38], 1`. This is the increment of the for counter meaning that if this line is hit, the comparison was successful.

We calculate the `hit_count` for the bruteforcing of the `i` character, if this value is greater than the `hit_count` for the `i-1` character of the flag, it means that the input string up to `i` is correct.

The maximum number of executions of the binary is = #printable_characters * flag_len.

