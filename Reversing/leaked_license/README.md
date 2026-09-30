# leaked_license

This challenge prints a `License number` associated with a `Serial code`.
The goal of the challenge and the flag is the `License number` associated with the `Serial code`: `726cfc2d26c6defedb06562199f5c7d0da4f4930`

The challenge can be solved using a debugger (gdb, pwndbg, ...) by following these steps:
- Break at 0x12C1, which corresponds to the assignment of a variable representing 8 consecutive characters of the `Serial Code`.
- Substitute, with the debugger, every piece of the starting license with the corresponding piece of the target license at these addresses:
    - $rsp + 0x40
    - $rsp + 0x38

```python
start_license_split = ["f3ed47e2","6e4de24a","41498194","5c7da2d","b1ac93d5"]
target_license_split = ["726cfc2d","26c6defe","db065621","99f5c7d0","da4f4930"]
```


