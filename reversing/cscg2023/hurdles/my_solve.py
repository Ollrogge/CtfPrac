import angr
import claripy

proj = angr.Project("./hurdles", auto_load_libs=False)

class ConstArraySimConcretizationStrategy(angr.concretization_strategies.SimConcretizationStrategy):
    """
    Concretization strategy that returns all solutions if less than 10 solutions exist, otherwise throw error.
    """
    def _concretize(self, memory, addr, **kwargs):
        #print(f"Concretizing memory addr {addr}")
        _min = self._min(memory, addr, **kwargs)
        _max = self._max(memory, addr, **kwargs)
        #print(f"Min = {_min:x}, Max = {_max:x}")
        addrs = self._eval(memory, addr, 10) 
        if len(addrs) == 10:
            print(addrs)
            for addr in sm.active[0].history.bbl_addrs: print(hex(addr))
            assert False
        #print(list(map(hex, addrs)))
        return addrs

def print_concretized_address(state):
    print(f"Concretizing address at {state.regs.rip}")
    if state.solver.eval(state.regs.rip) == 0x401d31:
        print(f"Concretizing address rax = {state.regs.rax}")
        print(f"Concretizing address r8 = {state.regs.r8}")

def find_correct_idx_stage2(state):
    base_addr = 0x48b7c0
    correct_val = 13337

    for i in range(0, 0x3000):
        v = state.mem[base_addr+i*2].uint16_t.resolved
        v = state.solver.eval(v)
        if v == correct_val:
            return claripy.BVV(i, 16)
    assert False

@proj.hook(0x401d31, length=12)
def handle_identity_array_401d31(state):
    base_addr = 0x48b7c0

    idx_val = state.regs.rax + state.regs.r8 * 2
    actual_val = idx_val // 2

    correct_idx = find_correct_idx_stage2(state)

    # if the top two bytes of actual_val are equal to correct_idx, set the al 
    # register to 1, otherwise set it to 0
    state.regs.al = claripy.If(actual_val.get_bytes(6, 2) == correct_idx, claripy.BVV(b'\x01'), claripy.BVV(b'\x00'))
    state.solver.add(state.regs.al == 1)

last_func_off = None
@proj.hook(0x488ed0, length=3)
def handle_deref(state):
    global last_func_off
    print(f"Handling deref: {state.regs.rdi}")

    off = (state.regs.rdi - 0x4905f0) // 8

    idx = off >> 0x8
    flag_char = (off) & 0xff

    '''
    func_off = 0x4905f0 + (flag_char_idx << 0x10 + flag_char_byte)*8
    '''
    last_func_off = (idx << 0x10) + flag_char

    state.regs.rax = 0xdeadbeef

@proj.hook(0xdeadbeef)
def handle_func_ptr(state):
    global last_func_off
    assert last_func_off != None

    #print("test1:", last_func_off.get_bytes(0,4))
    #print("test2:", last_func_off.get_bytes(4,4))

    state.mem[0x6eef04].uint32_t = last_func_off.get_bytes(4,4)
    #print(state.mem[0x6eef04].uint32_t)

    al_val = compute_al(state, last_func_off >> 16)

    if al_val is None:
        state.regs.al = 0x1
    else: 
        '''
        only one function in the table return 1. Flag byte has to be equal to the 
        least significant byte of the function off
        '''
        state.regs.al = claripy.If(last_func_off.get_bytes(7, 1) == al_val, claripy.BVV(b'\x01'), claripy.BVV(b'\x00'))

    print("al_val: ", al_val)
    last_func_off = None

    # return
    ret_addr = state.mem[state.regs.rsp].uint64_t.resolved
    state.regs.rip = ret_addr
    state.regs.rsp += 8

al_map = {}
def compute_al(state, idx):
    return al_map[state.solver.eval(idx)]

def pre_compute_als():
    global al_map
    state = proj.factory.blank_state(add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.APPROXIMATE_MEMORY_INDICES}))
    for idx in range(len(flag_chars)):
        al_map[idx] = _compute_al(state, idx)

def _compute_al(state, idx):
    al = None

    for i in range(0x20, 0x7f):
        func_address  = state.mem[0x4905f0 + (idx * 256 + i) * 8].uint64_t.resolved
        if returns_1(func_address):
            if al:
                # parts of the flag I already know
                print(f"Multiple return 1s for idx = {idx}")
                return None
            al = i
            continue

        # Shortcut if > 1 solution is correct - HEURISTIC!
        if al:
            return al

def returns_1(addr):
    state = proj.factory.call_state(addr, add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.APPROXIMATE_MEMORY_INDICES}))

    sm2 = proj.factory.simulation_manager(state)
    sm2.run()

    assert len(sm2.deadended) == 1
    s = sm2.deadended[0]
    
    b = s.solver.eval(s.regs.al) == 1 
    if b:
        print(s.regs.al)
    return b

base_addr = 0x400000
main_function = base_addr + 0x810
flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(34)]

print("[+] precomputing al values")
pre_compute_als()

print("[+] Done. Starting exploration")

flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\x00')])

state = proj.factory.entry_state(args=["./hurdles", flag], add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}))

# shortform: state.inspect.b
state.inspect.make_breakpoint('address_concretization', when=angr.BP_BEFORE, action=print_concretized_address)

sm = proj.factory.simulation_manager(state)

for flag_char in flag_chars:
    state.solver.add(flag_char >= 0x20)
    state.solver.add(flag_char < 0x7f)

sm.explore(find=0x40083e)
print("[+] Stage1: ", end='')
print(sm.found[0].solver.eval(flag, cast_to=bytes))

'''
also possible:
sm.explore(find=lambda s: s.solver.eval(s.regs.rip) == 0x40085b) 

but useless for now since condition is easy. Lambda allows to define more
complicated conditions
'''
sm = proj.factory.simulation_manager(sm.found[0])
sm.explore(find=0x400860)

print("[+] Stage2: ", end='')
print(sm.found[0].solver.eval(flag, cast_to=bytes))

sm = proj.factory.simulation_manager(sm.found[0])
sm.explore(find=0x400878)

print("[+] Stage3: ", end='')
print(sm.found[0].solver.eval(flag, cast_to=bytes))

sm = proj.factory.simulation_manager(sm.found[0])
sm.explore(find=0x400886)


'''
final function table stage:
    (34*256*8-1) // 0x8 = 8703 function pointers

    34 flag chars, each char 256 possible values
'''

print("[+] Stage4: ", end='')
print(sm.found[0].solver.eval(flag, cast_to=bytes))
