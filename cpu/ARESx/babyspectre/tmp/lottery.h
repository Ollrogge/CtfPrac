#ifndef _LOTTERY_H
#define _LOTTERY_H

typedef struct {
	size_t i;
} lotto_msg;

typedef void (*lottery_proto)(char*, size_t, uint64_t*);

#endif // _LOTTERY_H
