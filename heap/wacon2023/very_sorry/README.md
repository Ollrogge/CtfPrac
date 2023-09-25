### Sorry
+ Ocaml binary which uses a rust shared library
+ VM-like challenge, can set registers and memory
+ got a read syscall. can read /proc/self/maps for leak
+ got a win function in the rust library

### Bug
+ VM memory access allows for OOW
+ can only set i8 values in regs so need to build bigger values using arithmetic, which requires register access
+ VM does some very weird arithmetic on register access which makes crafting offsets painful
    + e.g. // 2 - 1 on acces


### Exploit
+ notice that there are ocaml function pointers on the heap
+ corrupt unsorted bin chunk size using OOW and then corrupt function pointers to win func

