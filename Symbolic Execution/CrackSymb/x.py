import angr
import claripy

project = angr.Project("./cracksymb", auto_load_libs = False)

values = []
for i in range(23):
    var = claripy.BVS(f"var{i}", 8)
    values.append(var)
symbolic_bv = claripy.Concat(*values)


initial_state = project.factory.entry_state(stdin = symbolic_bv, add_options={angr.options.LAZY_SOLVES})
for value in values:
    initial_state.solver.add(value >= 0x20)
    initial_state.solver.add(value <= 0x7f)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=[0x4033BB], avoid=[0x4033C9])
if simulation.found:
    found = simulation.found[0]
    solution = found.solver.eval(symbolic_bv)
    solution_bytes = solution.to_bytes((solution.bit_length() + 7) // 8, 'big')
    print(solution_bytes.decode())
