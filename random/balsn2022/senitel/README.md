## Challenge
* Challenge dynamically starts a docker container instance we run in
* Got access to a shell. Goal is to read flag file
* Challenge uses seccomp notify to monitor and handle syscalls that we make
* If we try to open flag it sabotages the FD to instead open a fake flag

## Solution
**unintended**
* use io_uring to read flag since syscall is not banned
**intended**
* monitoring thread calls fstat twice then compares if the file to be openened has the same inode value as the flag
* Due to the challenge using docker, overlayfs is used which copies files to upper layers if they are opened for writing / hardlinked. In this case the inode number of the file might change.
* Use the small window between the fstat calls to create a hardlink to the flag in the hope that this will result in the flag file getting a different inode

## Notes from ppl that solved it
The sentinel calls fstat twice. Once for the file you're trying to open and once for the flag, and compares the inode numbers
If the inode number of the flag changes between those two fstat calls you can read the flag
On overlayfs inode numbers can change if a file is copied to the upper layer which happens when the file is opened for writing, or when it's hardlinked somewhere
So there is a small race window between the two calls to fstat
If you can hardlink the flag somewhere (or change its indode number in some other way) during that window the sentinel will let you open the flag
The getdents spam is only there because the inode change only happens once so you can't spam link

If you link the flag too soon it won't work
So the idea is to use getdents to figure out when the sentinel has opened the flag for the first time
And link it only at that moment
It's still not perfect, the exploit takes a few tries to succeed, but it works
