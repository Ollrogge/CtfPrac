## Dice ctf 2021 Sice-sice baby

Bug: single nullbyte overflow

Exploit: Crazy heap feng shui in order to get House of Einherjar to work
         with mitigations in place. Lots of alignment crap


Only thing I learned, how to get 0x100 chunk if max allowed is 0x8e:
- to do this, we create a 0x1a0-sized unsortedbin, then allocate a 0xa0 sized chunk to leave a 0x100 unsortedbin.
- From there, a 0xe8 allocation will be served from the entire unsorted chunk.
- The way to get 0x100 chunks served on 0xe8 allocations was the detail I missed during the competition.
- I had already done a very similar massage before, so after getting that final detail the exploit was complete.

