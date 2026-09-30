import angr
import claripy
import string



class HookConvert(angr.SimProcedure):
    global values_addr

    def run(self):
        values = []
        for i in range(30):
            var = claripy.BVS(f"var_{i}", 8)
            fixed = claripy.BVV(0, 8*7)
            self.state.solver.add(var >= 0)
            self.state.solver.add(var <= 61)
            values.append(var)
            values.append(fixed)
        symbolic_bv = claripy.Concat(*values)
        self.state.memory.store(0x400000+0x5080, symbolic_bv)
        self.state.globals["symbolic_bv"] = symbolic_bv
        return 0



project = angr.Project("./downloads/challenge", auto_load_libs=False)
initial_state = project.factory.entry_state(args=["./downloads/challenge","AAAAA"])
values_addr = project.loader.find_symbol("values").rebased_addr
project.hook_symbol("convert", HookConvert())
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