## Google ctf 2021 eBPF

### Vuln
* patch changes `PTR_TO_MAP_VALUE` to a `SCALAR` when performing xor 
  operation on it
* peforming xor again changes the value back to a ptr
* Therefore, we can change a map ptr to arb addresses and have an arb r/w 
  primitive
