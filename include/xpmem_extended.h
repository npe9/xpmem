/*
 * Extended Private Cross Partition Memory (XPMEM) structures and macros.
 */

#ifndef _XPMEM_EXTENDED_H
#define _XPMEM_EXTENDED_H

#include <xpmem_private.h>
#include <xpmem.h>


extern u32 extend_enabled;
extern struct xpmem_extended_ops * xpmem_extended_ops;
extern struct xpmem_extended_ops palacios_ops;
extern struct xpmem_extended_ops ns_ops;

struct xpmem_extended_ops { 
    int (*make)(struct xpmem_partition *, xpmem_segid_t *); 
    int (*remove)(struct xpmem_partition *, xpmem_segid_t);
    int (*get)(struct xpmem_partition *, xpmem_segid_t, int, int, u64, xpmem_apid_t *); 
    int (*release)(struct xpmem_partition *, xpmem_apid_t);
    int (*attach)(struct xpmem_partition *, xpmem_apid_t, off_t, size_t, u64 *);
    int (*detach)(struct xpmem_partition *, u64);
};

struct xpmem_cmd_make_ex {
    xpmem_segid_t segid;
};

struct xpmem_cmd_remove_ex {
    xpmem_segid_t segid;
};

struct xpmem_cmd_get_ex {
    xpmem_segid_t segid;
    uint32_t flags;
    uint32_t permit_type;
    uint64_t permit_value;
    xpmem_apid_t apid;
};

struct xpmem_cmd_release_ex {
    xpmem_apid_t apid;
};

struct xpmem_cmd_attach_ex {
    xpmem_apid_t apid;
    uint64_t off;
    uint64_t size;
    uint64_t num_pfns;
    uint64_t * pfns;
};

struct xpmem_cmd_detach_ex {
    uint64_t vaddr;
};

typedef enum {
    XPMEM_MAKE,
    XPMEM_MAKE_COMPLETE,
    XPMEM_REMOVE,
    XPMEM_REMOVE_COMPLETE,
    XPMEM_GET,
    XPMEM_GET_COMPLETE,
    XPMEM_RELEASE,
    XPMEM_RELEASE_COMPLETE,
    XPMEM_ATTACH,
    XPMEM_ATTACH_COMPLETE,
    XPMEM_DETACH,
    XPMEM_DETACH_COMPLETE,
} xpmem_op_t;

typedef enum {
    LOCAL,
    VM, 
    ENCLAVE,
} xpmem_endpoint_t;

struct xpmem_loc {
    int fd; 

    xpmem_endpoint_t type;
    int id; 

    xpmem_endpoint_t type2;
    int id2;
};

struct xpmem_cmd_ex {
    xpmem_op_t type;
    union {
        struct xpmem_cmd_make_ex make;
        struct xpmem_cmd_remove_ex remove;
        struct xpmem_cmd_get_ex get;
        struct xpmem_cmd_release_ex release;
        struct xpmem_cmd_attach_ex attach;
        struct xpmem_cmd_detach_ex detach;
    };  
    struct xpmem_loc src_loc;
};

struct ns_xpmem_state {
    int initialized;

    /* pending/in progress command  */
    struct xpmem_cmd_ex cmd;
    int requested;
    int processed;
    int complete;

    /* protect cmd/req */
    spinlock_t lock;

    /* Serialize client access to NS */
    struct mutex mutex;

    /* waitq for clients */
    wait_queue_head_t client_wq;

    /* waitq for name server */
    wait_queue_head_t ns_wq;
};


int xpmem_get_remote(struct xpmem_cmd_get_ex * get_ex);
int xpmem_release_remote(struct xpmem_cmd_release_ex * release_ex);
int xpmem_attach_remote(struct xpmem_cmd_attach_ex * attach_ex);
int xpmem_detach_remote(struct xpmem_cmd_detach_ex * detach_ex);

#endif /* _XPMEM_EXTENDED_H */
