#ifndef __EVENTS_H__
#define __EVENTS_H__

#ifdef __USER_SPACE__
#include <stdint.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
#endif

enum event_kind {
    EVENT_API  = 1,
    EVENT_CONN = 2,
};

enum api_id {
    API_UNKNOWN = 0,
    API_HTTP_REGISTER_NF_INSTANCE = 1,
    API_HTTP_SEARCH_NF_INSTANCES  = 2,
    API_HTTP_GET_NF_INSTANCE      = 3,
};

struct api_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 kind;
    __u32 api_id;
};

struct conn_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 kind;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

#endif