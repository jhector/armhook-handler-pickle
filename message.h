#ifndef HANDLER_MESSAGE_H_
#define HANDLER_MESSAGE_H_

#include <stdint.h>

typedef struct __attribute__((packed)) {
        uint32_t payload_size;
        int32_t routing;
        uint32_t type;
        uint32_t flags;
        uint32_t num_fds;
        union {
                uint32_t interrupt_remote_stack_depth_guess;
                int32_t txid;
        };
        uint32_t interrupt_local_stack_depth;
        int32_t seqno;
} Header;

typedef struct __attribute__((packed)) {
        Header *header_;
        uint32_t header_size_;
        uint32_t capacity_;
        uint32_t variable_buffer_offset_;
        uint32_t file_descriptor_set_;
        const char *name_;
} IPCMessage;

#endif /* HANDLER_MESSAGE_H_ */
