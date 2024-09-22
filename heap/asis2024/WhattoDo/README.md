### C++ heap chall
+ Some c++ map storing our data
    + c++ map is implemented using a RBTree 

**Bug**
+ can pass -1 as size giving us a heap overflow and also leaks

**Exploit**
+ corrupt RBTree struct to get arbitrary read and write
+ overwrite return address with ropchain
