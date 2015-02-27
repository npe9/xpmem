/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_ns.c: The XPMEM name service
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <xpmem_private.h>
#include <xpmem_hashtable.h>

extern struct proc_dir_entry * xpmem_proc_dir;

/* Name server state */
struct xpmem_ns_state {
    /* lock for ns state */
    spinlock_t                     lock;

    /* list of free segids */
    struct list_head               segid_free_list;

    /* mappings of allocated segids */
    struct xpmem_hashtable       * segid_map;

    /* Apid management */
    struct xpmem_hashtable       * apid_map;

    /* Domain management */
    struct xpmem_domain          * domain_map[XPMEM_MAX_DOMID];
};


/* List node for name server unique segid accounting */
struct xpmem_segid_list_node {
    unsigned short   uniq;
    struct list_head list_node;
};

/* Hashtable key entry for segid/apid management */
struct xpmem_id_key {
    xpmem_segid_t segid;
    xpmem_apid_t  apid;
};

/* Hashtable value entry for segid/apid management */
struct xpmem_id_val {
    xpmem_segid_t    segid;
    xpmem_apid_t     apid;
    xpmem_domid_t    domid;
    xpmem_domid_t    dst_domid;

    /* Embedded in domain segid/apid list */
    struct list_head node;
};


/* Per-domain state */
struct xpmem_domain {
    /* Domain lock */
    spinlock_t              lock;

    /* Proc directory */
    struct proc_dir_entry * proc_dir;

    /* Assigned domid */
    xpmem_domid_t           domid;

    /* list of assigned segids */
    struct list_head        segid_list;
    /* Number of segids allocated */
    unsigned long           num_segids;

    /* list of attached apids */
    struct list_head        apid_list;
    /* Number of apids attached to */
    unsigned long           num_apids;
};


/* Segid map eq function */
static int
xpmem_segid_eq_fn(uintptr_t key1,
                  uintptr_t key2)
{
    struct xpmem_id_key * id1 = (struct xpmem_id_key *)key1;
    struct xpmem_id_key * id2 = (struct xpmem_id_key *)key2;

    return (id1->segid == id2->segid);
}

/* Apid map eq function */
static int
xpmem_apid_eq_fn(uintptr_t key1,
                 uintptr_t key2)
{
    struct xpmem_id_key * id1 = (struct xpmem_id_key *)key1;
    struct xpmem_id_key * id2 = (struct xpmem_id_key *)key2;
    
    return ((id1->segid == id2->segid) &&
            (id1->apid  == id2->apid)
           );
}

/* Segid map hash function */
static u32
xpmem_segid_hash_fn(uintptr_t key)
{
    struct xpmem_id_key * id = (struct xpmem_id_key *)key;

    return hash_long(id->segid);
}

/* Apid map hash function */
static u32
xpmem_apid_hash_fn(uintptr_t key)
{
    struct xpmem_id_key * id = (struct xpmem_id_key *)key;

    return hash_long(id->apid);
}


/* Hashtable helpers */
static int
xpmem_htable_add(struct xpmem_hashtable * ht,
                 uintptr_t                key,
                 uintptr_t                val)
{
    /* Search for duplicate first */
    if (htable_search(ht, key) != 0) {
        return 0;
    } else {
        return htable_insert(ht, key, val);
    }
}

static void
enclave_segid_show(struct seq_file     * file,
                   struct xpmem_domain * domain)
{
    struct xpmem_id_val * val = NULL;

    list_for_each_entry(val, &(domain->segid_list), node) {
        seq_printf(file, "%lli\n", 
            val->segid);
    }
}

static void
enclave_apid_show(struct seq_file     * file,
                  struct xpmem_domain * domain)
{
    struct xpmem_id_val * val = NULL;

    list_for_each_entry(val, &(domain->apid_list), node) {
        seq_printf(file, "%lli (segid=%llu), for domid %lli\n", 
            val->apid,
            val->segid,
            val->dst_domid);
    }
}

static int
proc_segid_show(struct seq_file * file,
                void            * private_data)
{
    struct xpmem_domain * domain = (struct xpmem_domain *)file->private;

    if (IS_ERR(domain)) {
        seq_printf(file, "NULL DOMID\n");
        return 0;
    }

    spin_lock(&(domain->lock));
    {
        enclave_segid_show(file, domain);
    }
    spin_unlock(&(domain->lock));

    return 0;
}

static int
proc_apid_show(struct seq_file * file,
               void            * private_data)
{
    struct xpmem_domain * domain = (struct xpmem_domain *)file->private;

    if (IS_ERR(domain)) {
        seq_printf(file, "NULL DOMID\n");
        return 0;
    }

    spin_lock(&(domain->lock));
    {
        enclave_apid_show(file, domain);
    }
    spin_unlock(&(domain->lock));

    return 0;
}

static int
proc_segid_open(struct inode * inode,
                struct file  * filp)
{

    struct xpmem_domain * domain = NULL;
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    domain = PDE(inode)->data;
#else
    domain = PDE_DATA(inode);
#endif

    return single_open(filp, proc_segid_show, domain);
}

static int
proc_apid_open(struct inode * inode,
               struct file  * filp)
{
    struct xpmem_domain * domain = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    domain = PDE(inode)->data;
#else
    domain = PDE_DATA(inode);
#endif

    return single_open(filp, proc_apid_show, domain);
}

static int
proc_release(struct inode * inode,
             struct file  * filp)
{
    return single_release(inode, filp);
}

static struct file_operations
proc_apid_fops =
{
    .owner   = THIS_MODULE,
    .open    = proc_apid_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = proc_release,
};

static struct file_operations
proc_segid_fops = 
{
    .owner   = THIS_MODULE,
    .open    = proc_segid_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = proc_release,
};


static void
domain_add_xpmem_segid(struct xpmem_domain * domain,
                       struct xpmem_id_val * val)
{
    INIT_LIST_HEAD(&(val->node));

    spin_lock(&(domain->lock));
    {
        list_add_tail(&(val->node), &(domain->segid_list));
        domain->num_segids++;
    }
    spin_unlock(&(domain->lock));
}

static void
domain_remove_xpmem_segid(struct xpmem_domain * domain,
                          struct xpmem_id_val * val)
{
    spin_lock(&(domain->lock));
    {
        list_del(&(val->node));
        domain->num_segids--;
    }
    spin_unlock(&(domain->lock));
}

static void
domain_add_xpmem_apid(struct xpmem_domain * domain, 
                      struct xpmem_id_val * val)
{
    INIT_LIST_HEAD(&(val->node));

    spin_lock(&(domain->lock));
    {
        list_add_tail(&(val->node), &(domain->apid_list));
        domain->num_apids++;
    }
    spin_unlock(&(domain->lock));
}

static void
domain_remove_xpmem_apid(struct xpmem_domain * domain,
                         struct xpmem_id_val * val)
{
    spin_lock(&(domain->lock));
    {
        list_del(&(val->node));
        domain->num_apids--;
    }
    spin_unlock(&(domain->lock));
}

static int
alloc_segid(struct xpmem_ns_state * ns_state,
            xpmem_segid_t         * segid)
{
    struct xpmem_segid_list_node * iter  = NULL;
    struct xpmem_id              * id    = NULL;

    /* Grab the first free segid */
    spin_lock(&(ns_state->lock));
    {
        if (!list_empty(&(ns_state->segid_free_list))) {
            iter = list_first_entry(&(ns_state->segid_free_list),
                        struct xpmem_segid_list_node,
                        list_node);
            list_del(&(iter->list_node));
        } else {
            iter = NULL;
        }
    }
    spin_unlock(&(ns_state->lock));

    if (iter == NULL) {
        return -1;
    }

    id       = (struct xpmem_id *)segid;
    id->uniq = (unsigned short)(iter->uniq);

    kfree(iter);

    return 0;
}

static void
free_segid(struct xpmem_ns_state * ns_state,
           xpmem_segid_t           segid)
{
    struct xpmem_segid_list_node * iter  = NULL;

    /* Nothing to do for well-known segids */
    if (segid <= XPMEM_MAX_WK_SEGID) 
        return;

    /* Add segid back to the free list */
    iter = kmalloc(sizeof(struct xpmem_segid_list_node), GFP_KERNEL);
    if (iter == NULL) {
        return;
    }

    iter->uniq = xpmem_segid_to_uniq(segid);

    spin_lock(&(ns_state->lock));
    {
        list_add_tail(&(iter->list_node), &(ns_state->segid_free_list));        
    }
    spin_unlock(&(ns_state->lock));
}

static int
alloc_xpmem_segid(struct xpmem_ns_state * ns_state, 
                  struct xpmem_domain   * domain,
                  xpmem_segid_t           request,
                  xpmem_segid_t         * segid)
{
    struct xpmem_id_key * key = NULL;
    struct xpmem_id_val * val = NULL;

    /* Generate a new segid */
    if (request > 0) {
        /* Explicit request */
        if (request > XPMEM_MAX_WK_SEGID) {
            XPMEM_ERR("Requested well-known segid %lli is invalid. Valid range is [%d:%d]",
                 request, 1, XPMEM_MAX_WK_SEGID);
            return -1;
        }

        *segid = request;
    } else {
        /* Grab a free segid */
        if (alloc_segid(ns_state, segid) != 0) {
            XPMEM_ERR("Cannot allocate new segid");
            return -1;
        }
    }

    /* Allocate htable key/value */
    key = kmalloc(sizeof(struct xpmem_id_key), GFP_KERNEL);
    if (key == NULL) {
        free_segid(ns_state, *segid);
        return -ENOMEM;
    }

    val = kmalloc(sizeof(struct xpmem_id_val), GFP_KERNEL);
    if (val == NULL) {
        kfree(key);
        free_segid(ns_state, *segid);
        return -ENOMEM;
    }

    /* Setup key */
    key->segid     = *segid;
    key->apid      = -1;

    /* Setup val */
    val->segid     = *segid;
    val->apid      = -1;
    val->domid     = domain->domid;
    val->dst_domid = -1;

    /* Add to domain list */
    domain_add_xpmem_segid(domain, val);

    /* Add to segid map */
    if (xpmem_htable_add(ns_state->segid_map, (uintptr_t)key, (uintptr_t)val) == 0) {
        XPMEM_ERR("Cannot add segid %lli to hashtable, probably because it has already been allocated", *segid);

        domain_remove_xpmem_segid(domain, val);
        free_segid(ns_state, *segid);

        kfree(val);
        kfree(key);

        return -1;
    }

    return 0;
}

static int
free_xpmem_segid(struct xpmem_ns_state * ns_state,
                 struct xpmem_domain   * domain,
                 xpmem_segid_t           segid)
{
    struct xpmem_id_key   search_key;
    struct xpmem_id_val * val = NULL;

    search_key.segid = segid;
    search_key.apid  = -1;

    /* First, search the hashtable for the domain */
    val = (struct xpmem_id_val *)htable_search(ns_state->segid_map, (uintptr_t)&search_key);

    if (val == NULL) {
        XPMEM_ERR("Cannot free segid %lli: cannot find source domain", segid);
        return -1;
    }

    /* Make sure it matches the source domain */
    if (val->domid != domain->domid) {
        XPMEM_ERR("Domain %lli trying to remove segid %lli, which was allocated to domain %lli",
            domain->domid, segid, val->domid);
        return -1;
    }

    /* Proceed with the removal */
    val = (struct xpmem_id_val *)htable_remove(ns_state->segid_map, (uintptr_t)&search_key, 1);

    /* Remove from domain list */
    domain_remove_xpmem_segid(domain, val);

    /* Free htable value */
    kfree(val);

    /* Add segid back to the free list */
    free_segid(ns_state, segid);

    return 0;
}


static int
add_xpmem_apid(struct xpmem_ns_state * ns_state, 
               struct xpmem_domain   * domain,
               struct xpmem_domain   * req_domain,
               xpmem_segid_t           segid,
               xpmem_apid_t            apid)
{
    struct xpmem_id_key * key = NULL;
    struct xpmem_id_val * val = NULL;

    key = kmalloc(sizeof(struct xpmem_id_key), GFP_KERNEL);
    if (key == NULL) {
        return -ENOMEM;
    }

    val = kmalloc(sizeof(struct xpmem_id_val), GFP_KERNEL);
    if (val == NULL) {
        kfree(key);
        return -ENOMEM;
    }

    /* Setup key */
    key->segid     = segid;
    key->apid      = apid;

    /* Setup val */
    val->segid     = segid;
    val->apid      = apid;
    val->domid     = domain->domid;
    val->dst_domid = req_domain->domid;

    /* Add to domain list */
    domain_add_xpmem_apid(domain, val);

    /* Add to apid map */
    if (xpmem_htable_add(ns_state->apid_map, (uintptr_t)key, (uintptr_t)val) == 0) {
        XPMEM_ERR("Cannot add apid %lli to hashtable, probably because it is already present", apid);

        domain_remove_xpmem_apid(domain, val);

        kfree(val);
        kfree(key);

        return -1;
    }

    return 0;
}

static int
remove_xpmem_apid(struct xpmem_ns_state * ns_state,
                  struct xpmem_domain   * domain,
                  xpmem_segid_t           segid,
                  xpmem_apid_t            apid)
{
    struct xpmem_id_key   search_key;
    struct xpmem_id_val * val = NULL;

    search_key.segid = segid;
    search_key.apid  = apid;

    /* Remove from hashtable */
    val = (struct xpmem_id_val *)htable_remove(ns_state->apid_map, (uintptr_t)&search_key, 1);

    /* Remove from domain list */
    domain_remove_xpmem_apid(domain, val);

    /* Free htable value */
    kfree(val);

    return 0;
}

static xpmem_domid_t
alloc_xpmem_domid(struct xpmem_ns_state * ns_state,
                  struct xpmem_domain   * domain,
                  xpmem_domid_t           domid)
{
    xpmem_domid_t allocated = -1;

    spin_lock(&(ns_state->lock));
    {
        if ((domid >= 0) &&
            (domid < XPMEM_MAX_DOMID))
        {
            if (ns_state->domain_map[domid] == NULL) {
                ns_state->domain_map[domid] = domain;
                allocated = domid;
            }
        } else 
        {
            int i = 0;
            for (i = XPMEM_MIN_DOMID; i < XPMEM_MAX_DOMID; i++) {
                if (ns_state->domain_map[i] == NULL) {
                    ns_state->domain_map[i] = domain;
                    allocated               = i;
                    break;
                }
            }
        }
    }
    spin_unlock(&(ns_state->lock));

    return allocated;
}

static void
free_xpmem_domid(struct xpmem_ns_state * ns_state,
                 xpmem_domid_t           domid)
{
    spin_lock(&(ns_state->lock));
    {
        ns_state->domain_map[domid] = NULL;
    }
    spin_unlock(&(ns_state->lock));
}

static struct xpmem_domain *
alloc_xpmem_domain(struct xpmem_ns_state * ns_state,
                   xpmem_domid_t           domid)
{
    struct xpmem_domain * domain = NULL;

    /* Create a new domain */
    domain = kmalloc(sizeof(struct xpmem_domain), GFP_KERNEL);

    if (domain == NULL) {
        return NULL;
    }

    /* Allocate a domain id */
    domain->domid = (xpmem_domid_t)alloc_xpmem_domid(ns_state, domain, domid);

    if (domain->domid == -1) {
        XPMEM_ERR("No free domids: cannot create new domain!");
        kfree(domain);
        return NULL;
    }

    /* Init segid/apid lists */
    INIT_LIST_HEAD(&(domain->segid_list));
    INIT_LIST_HEAD(&(domain->apid_list));
    spin_lock_init(&(domain->lock));
    domain->num_segids = 0;
    domain->num_apids  = 0;

    /* Create proc entries for this domain */
    {
        struct proc_dir_entry * segid_entry = NULL;
        struct proc_dir_entry * apid_entry  = NULL;
        char name[16];

        memset(name, 0, 16);
        snprintf(name, 16, "domid-%d", (int)domain->domid);

        /* Create domid proc dir */
        domain->proc_dir = proc_mkdir(name, xpmem_proc_dir);

        /* Create segid subdirectory */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        segid_entry = create_proc_entry("segids", 0444, domain->proc_dir);
        if (segid_entry) {
            segid_entry->proc_fops = &proc_segid_fops;
            segid_entry->data      = domain;
        }

        apid_entry  = create_proc_entry("remote-apids", 0444, domain->proc_dir);
        if (apid_entry) {
            apid_entry->proc_fops  = &proc_apid_fops;
            apid_entry->data       = domain;
        }
#else
        segid_entry = proc_create_data("segids", 0444, domain->proc_dir, &proc_segid_fops, domain);
        apid_entry  = proc_create_data("remote-apids",  0444, domain->proc_dir, &proc_apid_fops,  domain);
#endif
    }

    return domain;
}

static int
free_xpmem_domain(struct xpmem_ns_state * ns_state,
                  struct xpmem_domain   * domain)
{
    struct xpmem_id_val * iter, * next;

    /* Tear down proc dirs */
    {
        char name[16];

        memset(name, 0, 16);
        snprintf(name, 16, "domid-%d", (int)domain->domid);

        remove_proc_entry("segids", domain->proc_dir);
        remove_proc_entry("remote-apids", domain->proc_dir);
        remove_proc_entry(name, xpmem_proc_dir);
    }

    /* Free segid/apid lists */
    if (domain->num_segids > 0) {
        XPMEM_ERR("Domain %lli is being freed, but has %lu outstanding segids assigned to it!", 
            domain->domid, domain->num_segids);

        list_for_each_entry_safe(iter, next, &(domain->segid_list), node) {
            /* Free the segid */
            free_xpmem_segid(ns_state, domain, iter->segid); 
        }
    }

    if (domain->num_apids > 0) {
        XPMEM_ERR("Domain %lli is being freed, but has allocated %lu apids that have not been released!",
            domain->domid, domain->num_apids);

        list_for_each_entry_safe(iter, next, &(domain->apid_list), node) {
            /* Free the apid */
            remove_xpmem_apid(ns_state, domain, iter->segid, iter->apid); 
        }
    }

    /* Free domid */
    free_xpmem_domid(ns_state, domain->domid);

    /* Free domain */
    kfree(domain);

    return 0;
}

static int
free_all_xpmem_domains(struct xpmem_ns_state * ns_state)
{
    int i   = 0;
    int ret = 0;

    for (i = 0; i < XPMEM_MAX_DOMID; i++) {
        if (ns_state->domain_map[i] != NULL) {
            ret |= free_xpmem_domain(ns_state, ns_state->domain_map[i]);
            ns_state->domain_map[i] = NULL;
        }
    }

    return ret;
}


/* Process an XPMEM_PING/PONG_NS command */
static int
xpmem_ns_process_ping_cmd(struct xpmem_partition_state * part_state,
                          xpmem_link_t                   link,
                          struct xpmem_cmd_ex          * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex   * out_cmd  = cmd;
    xpmem_link_t            out_link = link;

    switch (cmd->type) {
        case XPMEM_PING_NS: {
            /* Respond with a PONG to the source */
            out_cmd->type = XPMEM_PONG_NS;
            break;
        }

        case XPMEM_PONG_NS: {
            /* We received a PONG. WTF */
            XPMEM_ERR("Name server received a PONG? Are there multiple name servers running?");
            return 0;
        }

        default: {
            XPMEM_ERR("Unknown PING operation: %s", xpmem_cmd_to_string(cmd->type));
            return -EINVAL;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        XPMEM_ERR("Cannot send command on link %d", link);
        return -EFAULT;
    }

    return 0;
}


/* Process an XPMEM_DOMID_REQUEST/RESPONSE command */
static int
xpmem_ns_process_domid_cmd(struct xpmem_partition_state * part_state,
                           struct xpmem_domain          * req_domain,
                           struct xpmem_domain          * src_domain,
                           xpmem_link_t                   link,
                           struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_ns_state * ns_state = part_state->ns_state;

    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex   * out_cmd  = cmd;
    xpmem_link_t            out_link = link;
    int                     status   = 0;

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            /* A domid is requested by someone downstream from us on 'link' */
            struct xpmem_domain * domain = alloc_xpmem_domain(ns_state, -1);

            if (domain == NULL) {
                XPMEM_ERR("Cannot create new domain");
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            out_cmd->domid_req.domid = domain->domid;

            /* Update link map */
            xpmem_add_domid_link(part_state, domain->domid, link);

            out_domid_req:
            {
                out_cmd->type    = XPMEM_DOMID_RESPONSE;
                out_cmd->src_dom = XPMEM_NS_DOMID;
            }

            break;
        }

        case XPMEM_DOMID_RESPONSE: {
            /* We've been allocated a domid. Interesting. */
            XPMEM_ERR("Name server has been allocated a domid? Are there multiple name servers running?");
            return 0;
        }

        case XPMEM_DOMID_RELEASE: {
            /* A domain has gone away - free it and release its domid */
            status = free_xpmem_domain(ns_state, req_domain);
            if (status < 0) {
                XPMEM_ERR("Cannot free domain");
                return status;
            }

            /* Update link map */
            xpmem_remove_domid_link(part_state, cmd->domid_req.domid);
            return 0;
        }
        default: {
            XPMEM_ERR("Unknown domid operation: %s", xpmem_cmd_to_string(cmd->type));
            return -EINVAL;
        }
    }

    /* Write the response */
    status = xpmem_send_cmd_link(part_state, out_link, out_cmd);

    if (status < 0) {
        XPMEM_ERR("Cannot send command on link %d", link);
        return -EFAULT;
    }

    return 0;
}



/* Process a regular XPMEM command. If we get here we are connected to the name
 * server already and have a domid
 */
static int
xpmem_ns_process_xpmem_cmd(struct xpmem_partition_state * part_state,
                           struct xpmem_domain          * req_domain,
                           struct xpmem_domain          * src_domain,
                           xpmem_link_t                   link,
                           struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_ns_state * ns_state = part_state->ns_state;

    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex   * out_cmd  = cmd;
    xpmem_link_t            out_link = link;

    switch (cmd->type) {
        case XPMEM_MAKE: {
            /* Allocate a unique segid to this domain */
            if (alloc_xpmem_segid(ns_state, req_domain, cmd->make.request, &(cmd->make.segid))) {
                XPMEM_ERR("Cannot allocate segid");
                out_cmd->make.segid = -1;
            }

            out_cmd->type    = XPMEM_MAKE_COMPLETE;
            out_cmd->dst_dom = cmd->src_dom;
            out_cmd->src_dom = XPMEM_NS_DOMID;

            break;
        }

        case XPMEM_REMOVE: {
            /* Free segid to free list */
            if (free_xpmem_segid(ns_state, req_domain, cmd->remove.segid)) {
                XPMEM_ERR("Cannot free segid %lli", cmd->remove.segid);
            }

            out_cmd->type    = XPMEM_REMOVE_COMPLETE;
            out_cmd->dst_dom = cmd->src_dom;
            out_cmd->src_dom = XPMEM_NS_DOMID;

            break;
        }

        case XPMEM_GET: {
            struct xpmem_id_val * val = NULL;
            struct xpmem_id_key   key;

            key.segid = cmd->get.segid;

            /* Search segid map */
            val = (struct xpmem_id_val *)htable_search(ns_state->segid_map, (uintptr_t)&key);

            if (val == NULL) {
                XPMEM_ERR("Cannot find segid %lli in hashtable. Cannot complete XPMEM_GET", cmd->get.segid);
                goto err_get;
            }

            /* Search link map for link */
            out_link = xpmem_get_domid_link(part_state, val->domid);

            if (out_link == 0) {
                XPMEM_ERR("Cannot find domid %lli in hashtable", val->domid);
                goto err_get;
            }

            out_cmd->dst_dom = val->domid;

            break;

            err_get:
            {
                out_cmd->get.apid = -1;
                out_cmd->type     = XPMEM_GET_COMPLETE;
                out_cmd->dst_dom  = cmd->src_dom;
                out_cmd->src_dom  = XPMEM_NS_DOMID;
                out_link          = link;
            }

            break;
        }

        case XPMEM_RELEASE: {
            struct xpmem_domain * apid_domain = NULL;
            struct xpmem_id_val * val         = NULL;
            struct xpmem_id_key   key;

            key.segid = cmd->release.segid;
            key.apid  = cmd->release.apid;

            /* Search apid map */
            val = (struct xpmem_id_val *)htable_search(ns_state->apid_map, (uintptr_t)&key);

            if (val == NULL) {
                XPMEM_ERR("Cannot find apid %lli in hashtable. Cannot complete XPMEM_RELEASE", cmd->release.apid);
                goto err_release;
            }

            /* Make sure the releasing domain has permission */
            if (val->dst_domid != req_domain->domid) {
                XPMEM_ERR("Domain %lli trying to release apid %lli, which was allocated to domain %lli",
                    req_domain->domid, cmd->release.apid, val->dst_domid);
                goto err_release;
            }

            /* Grab the apid's source domain from the domid */
            apid_domain = ns_state->domain_map[val->domid];

            /* Perform removal */
            if (remove_xpmem_apid(ns_state, apid_domain, cmd->release.segid, cmd->release.apid) != 0) {
                XPMEM_ERR("Cannot remove apid %lli. Cannot complete XPMEM_RELEASE", cmd->release.apid);
                goto err_release;
            }

            out_link         = xpmem_get_domid_link(part_state, val->domid);
            out_cmd->dst_dom = val->domid;

            break;

            err_release:
            {
                out_cmd->type    = XPMEM_RELEASE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = XPMEM_NS_DOMID;
                out_link         = link;
            }

            break;
        }

        case XPMEM_ATTACH: {
            struct xpmem_id_val * val = NULL;
            struct xpmem_id_key   key;

            key.segid = cmd->attach.segid;
            key.apid  = cmd->attach.apid;

            /* Search apid map */
            val = (struct xpmem_id_val *)htable_search(ns_state->apid_map, (uintptr_t)&key);

            if (val == NULL) {
                XPMEM_ERR("Cannot find apid %lli in hashtable. Cannot complete XPMEM_ATTACH", cmd->attach.apid);
                goto err_attach;
            }

            /* Make sure the attaching domain has permission */
            if (val->dst_domid != req_domain->domid) {
                XPMEM_ERR("Domain %lli trying to attach to apid %lli, which was allocated to domain %lli",
                    req_domain->domid, cmd->attach.apid, val->dst_domid);
                goto err_attach;
            }

            /* Search link map for link */
            out_link = xpmem_get_domid_link(part_state, val->domid);

            if (out_link == 0) {
                XPMEM_ERR("Cannot find domid %lli in hashtable", val->domid);
                goto err_attach;
            }

            out_cmd->dst_dom = val->domid;

            break;

            err_attach:
            {
                out_cmd->type    = XPMEM_ATTACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = XPMEM_NS_DOMID;
                out_link         = link;
            }

            break;
        }

        case XPMEM_DETACH: {
            /* Ignore detaches for now */
            {
                out_cmd->type    = XPMEM_DETACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = XPMEM_NS_DOMID;
                out_link         = link;
            }

            break;
        }

        case XPMEM_GET_COMPLETE: {
            /* Perform apid accounting */
            if (cmd->get.apid > 0) {
                if (add_xpmem_apid(ns_state, src_domain, req_domain, cmd->get.segid, cmd->get.apid) != 0) {
                    XPMEM_ERR("Cannot add apid %lli", cmd->get.apid);
                }
            }

            goto operation_complete;
        }

        case XPMEM_RELEASE_COMPLETE: 
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE:
        operation_complete: {

            /* The destination is now the original requesting domain */
            cmd->dst_dom = cmd->req_dom;

            /* Search for the appropriate link */
            out_link = xpmem_get_domid_link(part_state, cmd->dst_dom);

            if (out_link == 0) {
                XPMEM_ERR("Cannot find domid %lli", cmd->dst_dom);
                return -EFAULT;
            }

            break; 
        }


        default: {
            XPMEM_ERR("Unknown operation: %s", xpmem_cmd_to_string(cmd->type));
            return -EINVAL;
        }
    }

    /* The nameserver is now the source */
    cmd->src_dom = XPMEM_NS_DOMID;

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        XPMEM_ERR("Cannot send command on link %d", link);
        return -EFAULT;
    }

    return 0;
}


static void
prepare_domids(struct xpmem_partition_state * part_state,
               xpmem_link_t                   link,
               struct xpmem_cmd_ex          * cmd)
{
    /* If the source is local, we need to setup the domids for routing */
    if (link == part_state->local_link) {
        if (cmd->req_dom == 0) {
            /* The request is being generated here: set the req domid */
            cmd->req_dom = XPMEM_NS_DOMID;
        }

        /* Route to the NS - trivially */
        cmd->src_dom = XPMEM_NS_DOMID;
        cmd->dst_dom = XPMEM_NS_DOMID;
    }
}

static int
prepare_domains(struct xpmem_partition_state  * part_state,
                struct xpmem_cmd_ex           * cmd,
                struct xpmem_domain          ** req_domain,
                struct xpmem_domain          ** src_domain)
{
    struct xpmem_domain * r = NULL;
    struct xpmem_domain * s = NULL;

    xpmem_domid_t r_domid = cmd->req_dom;
    xpmem_domid_t s_domid = cmd->src_dom;
    xpmem_domid_t d_domid = cmd->dst_dom;

    /* Always make sure we are the destination */
    if (d_domid != XPMEM_NS_DOMID) {
        XPMEM_ERR("Name server processing errant command (dst domid:%lli, ns domid:%lli)",
            d_domid, (xpmem_domid_t)XPMEM_NS_DOMID);
        return -1;
    }

    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
            break;

        default:
            if ((r_domid <= 0) || 
                (r_domid >= XPMEM_MAX_DOMID))
            {
                XPMEM_ERR("Invalid request domid (%lli)", r_domid);
                return -1;
            }

            if ((s_domid <= 0) || 
                (s_domid >= XPMEM_MAX_DOMID))
            {
                XPMEM_ERR("Invalid source domid (%lli)", s_domid);
                return -1;
            }

            /* Grab the domains */
            r = part_state->ns_state->domain_map[r_domid];
            s = part_state->ns_state->domain_map[s_domid];

            if (r == NULL) {
                XPMEM_ERR("NULL request domain (domid:%lli)", r_domid);
                return -1;
            }

            if (s == NULL) {
                XPMEM_ERR("NULL source domain (domid:%lli)", s_domid);
                return -1;
            }

            /* Everything is fine */
            break;
    }

    *req_domain = r;
    *src_domain = s;

    return 0;
}


int
xpmem_ns_deliver_cmd(struct xpmem_partition_state * part_state,
                     xpmem_link_t                   link,
                     struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_domain * req_domain = NULL;
    struct xpmem_domain * src_domain = NULL;

    /* Prepare the domids for routing, if necessary */
    prepare_domids(part_state, link, cmd);
    
    /* Sanity check domains */
    if (prepare_domains(part_state, cmd, &req_domain, &src_domain) != 0) {
        XPMEM_ERR("Command with malformed domids: (req:%lli, src:%lli, dst:%lli)",
            cmd->req_dom, cmd->src_dom, cmd->dst_dom);
        return -EINVAL;
    }

    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
            return xpmem_ns_process_ping_cmd(part_state, link, cmd);

        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
        case XPMEM_DOMID_RELEASE:
            return xpmem_ns_process_domid_cmd(part_state, req_domain, src_domain, link, cmd);

        default:
            return xpmem_ns_process_xpmem_cmd(part_state, req_domain, src_domain, link, cmd);
    }   
}



int
xpmem_ns_init(struct xpmem_partition_state * part_state)
{
    struct xpmem_ns_state        * ns_state = NULL;
    struct xpmem_domain          * domain   = NULL;
    struct xpmem_segid_list_node * iter     = NULL;
    int                       i        = 0;

    ns_state = kmalloc(sizeof(struct xpmem_ns_state), GFP_KERNEL);
    if (!ns_state) {
        return -1;
    }

    /* Create segid map */
    ns_state->segid_map = create_htable(0, xpmem_segid_hash_fn, xpmem_segid_eq_fn);
    if (!ns_state->segid_map) {
        kfree(ns_state);
        return -1;
    }

    /* Create apid map */
    ns_state->apid_map  = create_htable(0, xpmem_apid_hash_fn, xpmem_apid_eq_fn);
    if (!ns_state->apid_map) {
        free_htable(ns_state->segid_map, 1, 1);
        kfree(ns_state);
        return -1;
    }

    /* Create everything else */
    spin_lock_init(&(ns_state->lock));
    INIT_LIST_HEAD(&(ns_state->segid_free_list));

    /* Name server partition has a well-known domid */
    part_state->ns_state = ns_state;

    /* Populate segid list */
    for (i = XPMEM_MAX_WK_SEGID + 1; i < XPMEM_MAX_UNIQ_ID; i++) {
        iter = kmalloc(sizeof(struct xpmem_segid_list_node), GFP_KERNEL);

        if (!iter) {
            goto err_malloc; 
        }

        iter->uniq = i;
        list_add_tail(&(iter->list_node), &(ns_state->segid_free_list));
    }

    /* Setup domain map */
    memset(ns_state->domain_map, 0, sizeof(struct xpmem_domain *) * XPMEM_MAX_DOMID);

    /* Add local domain */
    domain = alloc_xpmem_domain(ns_state, XPMEM_NS_DOMID);

    if (domain == NULL) {
        goto err_malloc;
    }

    printk("XPMEM name service initialized\n");

    return 0;

err_malloc:
    while (!list_empty(&(ns_state->segid_free_list))) {
        iter = list_first_entry(&(ns_state->segid_free_list),
                    struct xpmem_segid_list_node,
                    list_node);
        list_del(&(iter->list_node));
        kfree(iter);
    }

    free_htable(ns_state->apid_map, 1, 1);
    free_htable(ns_state->segid_map, 1, 1);

    kfree(ns_state);
    return -ENOMEM;
}

int
xpmem_ns_deinit(struct xpmem_partition_state * part_state)
{
    struct xpmem_ns_state * ns_state = part_state->ns_state;

    if (!ns_state) {
        return 0;
    }

    /* Free any remaining domains */
    free_all_xpmem_domains(ns_state);

    /* Free segid map */
    free_htable(ns_state->segid_map, 1, 1);

    /* Free apid map */
    free_htable(ns_state->apid_map, 1, 1);

    /* Free segid list */
    {
        struct xpmem_segid_list_node * iter, * next;

        list_for_each_entry_safe(iter, next, &(ns_state->segid_free_list), list_node) {
            list_del(&(iter->list_node));
            kfree(iter);
        }
    }
    
    /* Final cleanup */
    kfree(ns_state);
    part_state->ns_state = NULL;

    printk("XPMEM name service deinitialized\n");

    return 0;
}

void
xpmem_ns_kill_domain(struct xpmem_partition_state * part_state,
                     xpmem_domid_t                  domid)
{
    struct xpmem_ns_state * ns_state = part_state->ns_state;
    struct xpmem_domain   * domain   = ns_state->domain_map[domid];

    (void)free_xpmem_domain(ns_state, domain);
}
