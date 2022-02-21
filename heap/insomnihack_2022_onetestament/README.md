### Insomni'hack teaser 2022 onetestament

Heap exploit calloc

### Vuln
* off by one allowing to increase byte at off by one position by 1
* UAF

### Exploit
* get 1 chunk into unsorted bin (victim)
* use off by one to set `IS_MAPPED` flag in victim chunk
    * calloc won't zero the chunk since it thinks that is mmaped (alread zeroed)
        * => allows for leak
* leak main arena
* use UAF to free same chunk twice into 0x70 fastbin
* House of Spirit to get chunk overlapping with `__malloc_hook` (`find_fake_fast`)

### Resources
https://ctftime.org/writeup/32227