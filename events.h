/* General Schema/Structure Definition */

#ifndef __EVENTS_H__
#define __EVENTS_H__

// #ifdef __USER_SPACE__
// #include <stdint.h>
// typedef uint64_t __u64;
// typedef uint32_t __u32;
// typedef uint16_t __u16;
// typedef uint8_t __u8;
// #endif

enum direction_type {
    IN  = 0,
    OUT = 1,
};

struct debug_args {
    __u64 arg1, arg2, arg3, arg4;
    __u64 q[16];
    char buf0[64], buf1[64], buf3[64], buf4[64];
    __u64 p1, p2, p3, p4;
    __u64 l1, l2, l3, l4;
}

/* Event Schema (connection, api) */
struct event {
    // Timestamp
    __u64 ts;

    // Process (kernel)
    __u32 pid;               // process id
    __u32 tid;               // thread id
    __u64 cid;               // cgroup id
    // char func[64];           // the function that triggered

    // Application (L7)
    char nf[8];              // the running NF
    char api[32];            // the name of api
    // char method[8];          // type of request
    // __u8 direction;          // Entry or Exit
    // int ret;                 // return value or HTTP status


    // Network Level (L3-L4)
    // __u32 src_ip;
    // __u32 dest_ip;
    // __u16 src_port;
    // __u16 dest_port;

    // Auth
    char auth_id[32];
    char scope[32];

    // Args
    struct debug_args dbg;
};


#endif