# ODC CTF 2024/2025

This repository contains my solutions to the challenges of the
*Offensive and Defensive Cybersecurity* course (A.Y. 2024/2025) at Politecnico di Milano.



## Repo structure


| Category            | Challenges | Status |
|---------------------|:----------:|:------:|
| Shellcoding         |     6      |   ✅   |
| Reversing           |     7      |   ✅   |
| Symbolic Execution  |     3      |   ✅   |
| Mitigations         |     4      |   ✅   |
| ROP                 |     4      |   ✅   |
| Heap Exploitation   |     5      |   ✅   |
| Kernel Exploitation |     -      |   🚧   |
| Packing             |     -      |   🚧   |
| Race Conditions     |     -      |   🚧   |


✅ documented · 🚧 write-up in progress

- `category/`
  - `challenge/`
    - `downloads`: optional - contains all provided files for the challenge
    - `README.md`: write-up
    - `x.py`: exploit script
    - `challenge-name`: binary (may be patched with custom loader/libc by using `patchelf`)


## Attribution & License

For educational purposes only

Challenges are from the *Offensive and Defensive Cybersecurity* course
(A.Y. 2024/2025) at Politecnico di Milano and belong to their respective authors.

My contribution (the write-ups and exploit scripts in each challenge folder) is © 2025-2026 Matteo Maffesi and released under the MIT License.