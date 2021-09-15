import gdb
import struct

def read_mem8(addr):
    return struct.unpack('<Q', gdb.inferiors()[
                         0].read_memory(addr, 8).tobytes())[0]

def read_mem4(addr):
    return struct.unpack('<I', gdb.inferiors()[
                         0].read_memory(addr, 4).tobytes())[0]


def read_mem2(addr):
    return struct.unpack('<H', gdb.inferiors()[
                         0].read_memory(addr, 2).tobytes())[0]


def read_mem1(addr):
    return gdb.inferiors()[0].read_memory(addr, 1).tobytes()[0]

def read_memx(addr, x):
    return gdb.inferiors()[0].read_memory(addr, 1).tobytes()[0]

def read_reg(reg):
    return gdb.parse_and_eval(f"${reg}")

def read_addr(addr):
    return gdb.parse_and_eval(f"*{addr}")

def set_addr(addr, val):
    return gdb.execute(f"set *{addr}={val}")

def empty_obj():
    return type('', (), {})()

def print_queue(obj):
    print("*** Queue ***")
    print(f"addr: {hex(obj.addr)}")
    print(f"data_size: {obj.data_size}")
    print(f"queue_size: {hex(obj.queue_size)}")
    print(f"max_entries: {obj.max_entries}")
    print(f"queue_idx: {obj.idx}")
    print(f"queue_data: {hex(obj.data)}")
    print("")

def print_queue_entry(obj):
    print(f"addr: {hex(obj.addr)}")
    print(f"idx: {hex(obj.idx)}")
    print(f"data: {hex(obj.data)}")
    print(f"next: {hex(obj.next)}")
    print("")

class KQueueCommand(gdb.Command):
    def __init__(self):
        super(KQueueCommand, self).__init__("kq", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        addr = None
        if len(args) > 0:
            addr = int(args, 16)

        self.read_queues(addr)
    
    '''
    typedef struct{
        uint16_t data_size;
        uint64_t queue_size; /* This needs to handle larger numbers */
        uint32_t max_entries;
        uint16_t idx;
        char* data;
    }queue;

    data_size: 0
    queue_size: 8
    max_entries: 16
    idx: 20
    data: 24

    size = 32

    '''
    MAX_QUEUES = 5
    def read_queues(self, addr = None):
        if addr == None:
            addr = 0xffffffffc0002520

        for i in range(5):
            addr_queue = read_mem8(addr + i * 8)

            if addr_queue != 0:
                queue = empty_obj()
                queue.addr = addr_queue
                queue.data_size = read_mem2(addr_queue)
                queue.queue_size = read_mem8(addr_queue + 8)
                queue.max_entries = read_mem4(addr_queue + 16)
                queue.idx = read_mem2(addr_queue + 20)
                queue.data = read_mem8(addr_queue + 24)

                print_queue(queue)

                #self.read_entries(queue)
        


    '''
    struct queue_entry{
        uint16_t idx;
        char *data;
        queue_entry *next;
    };

    queue entry:
    idx: 0
    data: 8
    next: 16

    size = 24
    '''
    def read_entries(self, queue):
        addr = queue.addr + 0x20
        while True:  
            queue_entry = empty_obj()
            queue_entry.addr = addr
            queue_entry.idx = read_mem2(addr)
            queue_entry.data = read_mem8(addr + 8)
            queue_entry.next = read_mem8(addr + 16)

            print_queue_entry(queue_entry)

            if queue_entry.next == 0:
                break
            else:
                addr = queue_entry.next


KQueueCommand()
