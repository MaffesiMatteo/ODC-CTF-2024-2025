# RevMeMP

The binary uses an anti-debugging technique (ptrace), so we cannot solve the challenge with a debugger as we did for RevMeM.

The solution is to reverse the function: since it uses a static seed for srand, we can write C code that reproduces the logic inside the binary to get the flag (`x.c`).