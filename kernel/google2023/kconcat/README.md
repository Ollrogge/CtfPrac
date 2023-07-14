
### Vulns
1. can trick driver into giving us "admin" rights by causing a setuid programm to
call ioctl on the driver

2. read functionality of the driver uses a different mutex than the remove functionality

### Exploit
+ get admin rights
+ create a fifo pipe
+ start a thread which tries to read from the fifo pipe. Will block until data is written to the pipe
+ once thread is blocked, use 'admin' remove functionality to free all messages, including the one the waiting thread is about to write to
+ spray tty_structs
+ write to fifo pipe, unblocking waiting thread which will read from the pipe and write the contents to a freed chunk which now contains a tty_struct
+ corrupt tty_struct to first leak stuff (k_base / heap) and later gain code execution by overwriting core_pattern using gagdet stored in tty_ops->ioctl ptr


### Resources
+ author writeup: https://github.com/google/google-ctf/tree/master/2023/pwn-kconcat/challenge
