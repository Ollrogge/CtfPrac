### Exploits tldr
+ challenge introduces custom syscall called “corctf_crash” which, after clearing the stack (to remove pt_regs), jumps to an arbitrary address with an arbitrary argument.

**`exp.c`**
1. Leak `kernel_base` using entrybleed attack
2. Overwrite `panic_on_ops` with 0 such that kernel doesn't shut down when oops occurs
3. Get a heap leak from registers of oops message
4. Spray a bunch of `cred` structs by `forking` processes
5. Write zeroes to heap, trying to corrupt UID related members of any `cred` struct
6. If root in any of the processes, copy flag to user directory and make it readable

> Note: there are a lot of kernel stack traces when the spray workers crash. Can ignore them and just check if the flag has been copied to user directory

**`exp2.c`**
1. Leak `kernel_base` using entrybleed attack
2. Leak `physmap` by doing an early return to userspace (`swapgs, sysret`)
    + physmap pointer in `r14` inside stacktrace
3. Calculate cpu_entry_area from phys_map as it is at a constant offset
4. Put ropchain into exception stack (`cea_exception_stacks`) by causing an exception
5. Calculate exception stack address inside physmap based on `cpu_enty_area` address
6. Stack pivot to our ropchain stored in the cea exception stack
> Note: If an exception occurs in between step 4 and 6, the exploit wont work

**`exp3.c`**
+ exploit described in writeup: https://kqx.io/writeups/zenerational/
1. Leak `kernel_base` using entrybleed attack
2. Leak `physmap` by doing an early return to userspace (`swapgs, sysret`)
    + physmap pointer in `r14` inside stacktrace
3. Calculate cpu_entry_area from phys_map as it is at a constant offset
4. Setup fake iretframe in registers, cause exception to write it to the exception stack
5. Use `corcrash` to jump to `swapgs_restore` gadget, returning to userspace and executing the `win` function