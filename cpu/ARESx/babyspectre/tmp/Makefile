all: sandbox/lottery

sandbox/lottery: lottery.c
	gcc -o $@ $< -O0 -lrt -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -static
