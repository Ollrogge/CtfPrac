**description**
* uaf on kmalloc 128 chunk
* all mitigations on

**solution**
* use uaf to corrupt msg_msg struct and overwrite m_ts member and leak
  data after msg_msg object to get kernel leak
* use the structure of the driver to gain information about slab addresses
* allocate another msg_msg obj => put into the slab we have uaf on
* free two slabs we know the addresses of and calculate the random value used
  in order to defeat the freelist hardening (encrypted next_ptr).
* free the previously freed msg_msg obj and corrupt the next pointer to 
  modprobe_path using the uaf
* win
