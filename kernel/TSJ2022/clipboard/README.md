## Vuln
* TOCTU vuln due to length being checked first in check_*_query and afterwards used in *_clipboard_data.

## Exploit 1
* Use userfaultfd to cause two page faults by aligning the query struct at a page boundary
    * Use first page fault to pass the length check
    * Increase the length in the second page fault to read / write out of bounds
* Overwrite a tty_struct ops pointer with a `mov dword ptr [rsi], edx ; ret` gadget
* Use gadget to overwrite modprobe path

## Exploit 2
* Create simple UAF by opening device twice and closing 1 file descriptor
* Use UAF to overwrite tty ops pointer with read gadget
* Use read gadget to scan heap and leak flag
    * Leverage fact that challenge uses initramfs and therefore the contents of all files is on the heap
