#!/usr/bin/python3

import angr
import claripy
import multiprocessing
import os
import json


base_addr = 0x400000
main_function = base_addr + 0x810
p = angr.Project("hurdles", auto_load_libs=False)

sm = None

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(34)]

def load_string(state, addr, length):
    r = b""
    for i in range(length):
        byt = state.mem[addr+i].uint8_t.resolved
        byt = state.solver.eval(byt)
        r += bytes([byt])
    return r

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

argv_addr  = 0xdead0000
argv1_addr = 0xdead0020
argv2_addr = 0xdead0040

state = p.factory.call_state(main_function, 2, argv_addr, add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}))

state.memory.read_strategies.insert(0, ConstArraySimConcretizationStrategy())

def print_concretized_address(state):
    print(f"Concretizing address at {state.regs.rip}")
    if state.solver.eval(state.regs.rip) == 0x401d31:
        print(f"Concretizing address rax = {state.regs.rax}")
        print(f"Concretizing address r8 = {state.regs.r8}")

def find_correct_idx_stage2(state):
    base_addr = 0x48b7c0
    correct_val = 13337

    for i in range(0, 0x2710):
        v = state.mem[base_addr+i*2].uint16_t.resolved
        v = state.solver.eval(v)
        if v == correct_val:
            return claripy.BVV(i, 16)
    assert False


@p.hook(0x401d31, length=12)
def handle_identity_array_401d31(state):
    base_addr = 0x48b7c0

    idx_val = state.regs.rax + state.regs.r8 * 2
    actual_val = idx_val // 2

    correct_idx = find_correct_idx_stage2(state)

    state.regs.al = claripy.If(actual_val.get_bytes(6, 2) == correct_idx, claripy.BVV(b'\x01'), claripy.BVV(b'\x00'))
    state.solver.add(state.regs.al == 1)


def returns_1(function):
    state = p.factory.call_state(function, add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.APPROXIMATE_MEMORY_INDICES}))
    sm2 = p.factory.simulation_manager(state)
    sm2.run()
    #print(sm2)
    #print(sm2.deadended[0].regs.al)

    assert len(sm2.deadended) == 1
    s = sm2.deadended[0]
    
    b = s.solver.eval(s.regs.al) == 1 
    if b:
        print(s.regs.al)
    return b


al_map = {}

def _compute_al(state, idx):
    al = None

    for i in range(0x20, 0x7f):
        func_address  = state.mem[0x4905f0 + (idx * 256 + i) * 8].uint64_t.resolved
        if returns_1(func_address):
            if al:
                print(f"Multiple return 1s for idx = {idx}")
                return None
            al = i
            continue

        # Shortcut if > 1 solution is correct - HEURISTIC!
        if al:
            return al
    

def pre_compute_als():
    global al_map
    if os.path.exists('als.json'):
        # load from cache
        with open('als.json', 'r') as f:
            al_map = json.load(f)
        return
    state = p.factory.blank_state(add_options=({angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.APPROXIMATE_MEMORY_INDICES}))
    for idx in range(len(flag_chars)):
        al_map[idx] = _compute_al(state, idx)
    with open('als.json', 'w') as f:
        json.dump(al_map, f)

pre_compute_als()

def compute_al(state, idx):
    return al_map[state.solver.eval(idx)]

last_funcptr_off = None
@p.hook(0xaaaa000000)
def handle_funcptr_call(state):
    global last_funcptr_off

    print(f"funcptr call with last_funcptr_off = {last_funcptr_off}")
    # set val
    assert last_funcptr_off is not None
    state.mem[0x6eef04].uint32_t = last_funcptr_off.get_bytes(4, 4)
    print(state.mem[0x6eef00].uint32_t)

    al_val = compute_al(state, last_funcptr_off >> 16)

    print(al_val)

    if al_val is None:
        state.regs.al = 1
    else:
        state.regs.al = claripy.If(last_funcptr_off.get_bytes(7, 1) == al_val, claripy.BVV(b'\x01'), claripy.BVV(b'\x00'))

    print(state.regs.al)

    last_funcptr_off = None

    # return
    ret_addr = state.mem[state.regs.rsp].uint64_t.resolved
    print(f"returning to: {ret_addr}")
    state.regs.rip = ret_addr
    state.regs.rsp += 8



@p.hook(0x488ed0, length=3)
def handle_488ed0(state):
    print(f"handling e88ed0, rdi = '{state.regs.rdi}'")

    global last_funcptr_off
    array_off = ((state.regs.rdi - 0x4905f0) // 8)
    last_funcptr_off = ((array_off >> 8) << 16) + (array_off & 0xff)
    state.regs.rax = 0xaaaa000000


state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=print_concretized_address)

flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\x00')])

state.mem[argv_addr].uint64_t = argv1_addr
state.mem[argv_addr+8].uint64_t = argv2_addr
state.mem[argv_addr+0x10].uint64_t = 0
state.memory.store(argv1_addr, b"./linear_code\x00") 
state.memory.store(argv2_addr, flag) 

for flag_char in flag_chars:
    if isinstance(flag_char, int):
        continue
    state.solver.add(flag_char >= 0x20)
    state.solver.add(flag_char <= 0x7f)

sm = p.factory.simulation_manager(state)


sm.explore(find=lambda s: s.solver.eval(s.regs.rip) == 0x40085b)

state = sm.found[0]
print(state.posix.dumps(1))


sm = p.factory.simulation_manager(state)

sm.explore(find=lambda s: s.solver.eval(s.regs.rip) == 0x400881)


if sm.errored:
    print(sm.errored)

for s in sm.found:
    print(s.regs.al)
    print(s.regs.eax)
    print(s.regs.rax)
    _flag_out = b""
    for flag_char in flag_chars:
        _flag_out += bytes([s.solver.eval(flag_char)])
    print(_flag_out)
    print(s.posix.dumps(1))

    #for addr in s.history.bbl_addrs: print(hex(addr))

#for s in sm.active:
#    _flag_out = b""
#    for flag_char in flag_chars:
#        _flag_out += bytes([s.solver.eval(flag_char)])
#    print(_flag_out)
#
for s in sm.deadended:
    print("deadended at:")
    print(s.regs.rip)
    #    _flag_out = b""
    #    for flag_char in flag_chars:
    #        _flag_out += bytes([s.solver.eval(flag_char)])
    #    print(_flag_out)
    #    print(hex(s.solver.eval(s.regs.rip)))
    #for addr in s.history.bbl_addrs: print(hex(addr))
    #print(s.posix.dumps(1))
#print(sm.deadended)


print(sm)

