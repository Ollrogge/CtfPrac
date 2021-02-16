## hashbrown kernel exploitation from dice ctf 2021.

Bug: Race condition which enables UAF.

Exploit:
- use userfaultfd to always win race
- UAF with shm_file_data to leak kernel pointer and defeat KASLR
- UAF to overwrite modprobe_path to shellscript which overwrites flag permissions
