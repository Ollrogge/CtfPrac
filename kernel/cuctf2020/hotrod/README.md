
**Bug**
* kernel module uses unlocked_ioctl but no locking
* enables us to create UAF scenario by using userfaultfd handler

**Exploit**
* corrupt timerfd_ctx structure and overwrite timderfd_tmrproc 
  pointer to pivot into rop chain

**Writeup**
* https://syst3mfailure.io/hotrod
