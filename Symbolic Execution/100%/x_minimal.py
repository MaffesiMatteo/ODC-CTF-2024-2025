import angr
import claripy
import string



project = angr.Project("./downloads/challenge", auto_load_libs=False)
check_function_addr = project.loader.find_symbol("check").rebased_addr
initial_state = project.factory.blank_state(addr = check_function_addr)
#setting registers
initial_state.regs.rsp = 0x600000
#setting memory
values_addr = project.loader.find_symbol("values").rebased_addr
values = []
for i in range(30):
    var = claripy.BVS(f"var_{i}", 8)
    fixed = claripy.BVV(0, 8*7)
    initial_state.solver.add(var >= 0)
    initial_state.solver.add(var <= 61)
    values.append(var)
    values.append(fixed)
symbolic_bv = claripy.Concat(*values)
initial_state.memory.store(0x400000+0x5080, symbolic_bv)
initial_state.globals["symbolic_bv"] = symbolic_bv
#running the simulation
simulation = project.factory.simgr(initial_state)
simulation.explore(find=[0x400000+0x21C5], avoid=[0x400000+0x21CC])
if simulation.found:
    found = simulation.found[0]
    solution = found.solver.eval(found.globals["symbolic_bv"], cast_to=bytes)
    sol = ""
    symbols = string.digits + string.ascii_letters
    for i in range(0, 30*8,8):
        sol += symbols[solution[i]]
    print(sol)