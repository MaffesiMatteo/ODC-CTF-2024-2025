from libdebug import debugger
import string

#needed for the bp to work
def provolino(t, bp):
    pass

d = debugger("./provola")

flag = b"$"*37
counter_max = 0


for i in range(37):
    for j in string.printable:
        flag_new = flag[:i] + j.encode() + flag[i+1:]

        r = d.run()

        bp = d.breakpoint(0x1A0F,file='provola' ,callback=provolino)
        
        d.cont()
    
        r.recvuntil(b'password.')
        r.sendline(flag_new)

        d.wait()
        d.kill()

        if bp.hit_count > counter_max:
            counter_max = bp.hit_count
            flag = flag_new
            print(flag)
            break

  
        


