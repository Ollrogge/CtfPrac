all: sandbox/lottery sandbox/exp

sandbox/lottery: lottery.c
	gcc -o $@ $< -O0 -lrt -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -static

sandbox/exp: exp.c
	gcc -o $@ $< -O0 -lrt -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -static
