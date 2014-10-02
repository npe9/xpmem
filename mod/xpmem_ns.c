/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_ns.c: The XPMEM name service
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>

#include <xpmem.h>
#include <xpmem_iface.h>
#include <xpmem_extended.h>
#include <xpmem_private.h>
#include <xpmem_hashtable.h>

#define XPMEM_MIN_SEGID    32
#define XPMEM_MIN_DOMID    32
#define XPMEM_MAX_DOMID    128



extern struct proc_dir_entry * xpmem_proc_dir;


/* Name server state */
struct xpmem_ns_state {
    /* lock for ns state */
    spinlock_t                     lock;

    /* Segid management */
    struct list_head               segid_free_list;
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

/* Segid map hash function */
static u32
xpmem_apid_hash_fn(uintptr_t key)
{
    struct xpmem_id_key * id = (struct xpmem_id_key *)key;

    return hash_long(id->apid);
}


/* Hashtable helpers */
static int
xpmem_ht_add_id(struct xpmem_ns_state  * ns_state,
                struct xpmem_hashtable * ht,
                struct xpmem_id_key    * key,
                struct xpmem_id_val    * val)
{
    unsigned long flags  = 0;
    int           status = 0;

    spin_lock_irqsave(&(ns_state->lock), flags);
    {
        status = htable_insert(ht, (uintptr_t)key, (uintptr_t)val);
    }
    spin_unlock_irqrestore(&(ns_state->lock), flags);

    return status;
}

static struct xpmem_id_val *
xpmem_ht_search_or_remove_id(struct xpmem_ns_state  * ns_state,
                             struct xpmem_hashtable * ht,
                             struct xpmem_id_key      search_key,
                             int                      remove)
{
    struct xpmem_id_val * val    = NULL;
    unsigned long         flags  = 0;

    spin_lock_irqsave(&(ns_state->lock), flags);
    {
        if (remove) {
            val = (struct xpmem_id_val *)htable_remove(ht, (uintptr_t)&search_key, 1);
        } else {
            val = (struct xpmem_id_val *)htable_search(ht, (uintptr_t)&search_key);
        }
    }
    spin_unlock_irqrestore(&(ns_state->lock), flags);

    return val;
}

static struct xpmem_id_val *
xpmem_ht_search_id(struct xpmem_ns_state  * ns_state,
                   struct xpmem_hashtable * ht,
                   struct xpmem_id_key      search_key)
{
    return xpmem_ht_search_or_remove_id(ns_state, ht, search_key, 0);
}

static struct xpmem_id_val *
xpmem_ht_remove_id(struct xpmem_ns_state  * ns_state,
                   struct xpmem_hashtable * ht,
                   struct xpmem_id_key      search_key)
{
    return xpmem_ht_search_or_remove_id(ns_state, ht, search_key, 1);
}


static void
enclave_segid_show(struct seq_file     * file,
                   struct xpmem_domain * domain)
{
    struct xpmem_id_val * val = NULL;

    seq_printf(file, "Domain %lli has the following %lu segids\n", 
        domain->domid,
        domain->num_segids);

    list_for_each_entry(val, &(domain->segid_list), node) {
        seq_printf(file, "  %lli (tgid = %d, uniq = %u)\n", 
            val->segid,
            xpmem_segid_to_tgid(val->segid),
            xpmem_segid_to_uniq(val->segid));
    }
}

static void
enclave_apid_show(struct seq_file     * file,
                  struct xpmem_domain * domain)
{
    struct xpmem_id_val * val = NULL;

    seq_printf(file, "Domain %lli has allocated the following %lu remote apids\n", 
        domain->domid,
        domain->num_apids);

    list_for_each_entry(val, &(domain->apid_list), node) {
        seq_printf(file, "  %lli (tgid = %d, uniq = %u, segid=%llu), for domid %lli\n", 
            val->apid,
            xpmem_apid_to_tgid(val->apid),
            xpmem_apid_to_uniq(val->apid),
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
    unsigned long flags = 0;

    INIT_LIST_HEAD(&(val->node));

    spin_lock_irqsave(&(domain->lock), flags);
    {
        list_add_tail(&(val->node), &(domain->segid_list));
        domain->num_segids++;
    }
    spin_unlock_irqrestore(&(domain->lock), flags);
}

static void
domain_remove_xpmem_segid(struct xpmem_domain * domain,
                          struct xpmem_id_val * val)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&(domain->lock), flags);
    {
        list_del(&(val->node));
        domain->num_segids--;
    }
    spin_unlock_irqrestore(&(domain->lock), flags);
}

static void
domain_add_xpmem_apid(struct xpmem_domain * domain, 
                      struct xpmem_id_val * val)
{
    unsigned long flags = 0;

    INIT_LIST_HEAD(&(val->node));

    spin_lock_irqsave(&(domain->lock), flags);
    {
        list_add_tail(&(val->node), &(domain->apid_list));
        domain->num_apids++;
    }
    spin_unlock_irqrestore(&(domain->lock), flags);
}

static void
domain_remove_xpmem_apid(struct xpmem_domain * domain,
                         struct xpmem_id_val * val)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&(domain->lock), flags);
    {
        list_del(&(val->node));
        domain->num_apids--;
    }
    spin_unlock_irqrestore(&(domain->lock), flags);
}
                   

static int
alloc_xpmem_segid(struct xpmem_ns_state * ns_state, 
                  struct xpmem_domain   * domain,
                  xpmem_segid_t         * segid)
{
    struct xpmem_segid_list_node * iter  = NULL;
    struct xpmem_id              * id    = NULL;
    struct xpmem_id_key          * key   = NULL;
    struct xpmem_id_val          * val   = NULL;

    key = kmalloc(sizeof(struct xpmem_id_key), GFP_KERNEL);
    if (key == NULL) {
        return -ENOMEM;
    }

    val = kmalloc(sizeof(struct xpmem_id_val), GFP_KERNEL);
    if (val == NULL) {
        kfree(key);
        return -ENOMEM;
    }

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
        kfree(key);
        kfree(val);
        return -1;
    }

    id       = (struct xpmem_id *)segid;
    id->uniq = (unsigned short)(iter->uniq);

    kfree(iter);

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
    if (xpmem_ht_add_id(ns_state, ns_state->segid_map, key, val) == 0) {
        XPMEM_ERR("Cannot add segid %lli to hashtable", *segid);
        domain_remove_xpmem_segid(domain, val);
        return -1;
    }

    return 0;
}

static int
free_xpmem_segid(struct xpmem_ns_state * ns_state,
                 struct xpmem_domain   * domain,
                 xpmem_segid_t           segid)
{
    struct xpmem_segid_list_node * iter       = NULL;
    struct xpmem_id_val          * val        = NULL;
    struct xpmem_id_key            search_key;

    search_key.segid = segid;
    search_key.apid  = -1;

    /* First, search the hashtable for the domain */
    val = xpmem_ht_search_id(ns_state, ns_state->segid_map, search_key);

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
    val = xpmem_ht_remove_id(ns_state, ns_state->segid_map, search_key);

    /* Remove from domain list */
    domain_remove_xpmem_segid(domain, val);

    /* Add segid back to the free list */
    iter = kmalloc(sizeof(struct xpmem_segid_list_node), GFP_KERNEL);
    if (iter == NULL) {
        return -1;
    }

    iter->uniq = xpmem_segid_to_uniq(segid);

    spin_lock(&(ns_state->lock));
    {
        list_add_tail(&(iter->list_node), &(ns_state->segid_free_list));        
    }
    spin_unlock(&(ns_state->lock));

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

    val->segid     = segid;
    val->apid      = apid;
    val->domid     = domain->domid;
    val->dst_domid = req_domain->domid;

    /* Add to domain list */
    domain_add_xpmem_apid(domain, val);

    /* Add to apid map */
    if (xpmem_ht_add_id(ns_state, ns_state->apid_map, key, val) == 0) {
        XPMEM_ERR("Cannot add apid %lli to hashtable", apid);
        domain_remove_xpmem_apid(domain, val);
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
    struct xpmem_id_val * val        = NULL;
    struct xpmem_id_key   search_key;

    search_key.segid = segid;
    search_key.apid  = apid;

    /* Remove from hashtable */
    val = xpmem_ht_remove_id(ns_state, ns_state->apid_map, search_key);

    /* Remove from domain list */
    domain_remove_xpmem_apid(domain, val);

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
    ns_state->domain_map[domid] = NULL;
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
            list_del(&(iter->node)); 

            /* Free the segid */
            free_xpmem_segid(ns_state, domain, iter->segid); 

            kfree(iter);
        }
    }

    if (domain->num_apids > 0) {
        XPMEM_ERR("Domain %lli is being freed, but has allocated %lu apids that have not been released!",
            domain->domid, domain->num_apids);

        list_for_each_entry_safe(iter, next, &(domain->apid_list), node) {
            list_del(&(iter->node)); 

            /* Free the apid */
            remove_xpmem_apid(ns_state, domain, iter->segid, iter->apid); 

            kfree(iter);
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
static void
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
            return;
        }

        default: {
            XPMEM_ERR("Unknown PING operation: %s", cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        XPMEM_ERR("Cannot send command on link %lli", link);
    }
}


/* Process an XPMEM_DOMID_REQUEST/RESPONSE command */
static void
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

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            struct xpmem_domain * domain = NULL;
            int ret = 0;

            /* A domid is requested by someone downstream from us on 'link' */
            domain = alloc_xpmem_domain(ns_state, -1);

            if (domain == NULL) {
                XPMEM_ERR("Cannot create new domain");
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            out_cmd->domid_req.domid = domain->domid;

            /* Update domid map */
            ret = xpmem_add_domid(part_state, domain->domid, link);

            if (ret == 0) {
                XPMEM_ERR("Cannot insert domid %lli into hashtable", domain->domid);
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            out_domid_req:
            {
                out_cmd->type    = XPMEM_DOMID_RESPONSE;
                out_cmd->src_dom = part_state->domid;
            }

            break;
        }

        case XPMEM_DOMID_RESPONSE: {
            /* We've been allocated a domid. Interesting. */
            XPMEM_ERR("Name server has been allocated a domid? Are there multiple name servers running?");
            return;
        }

        case XPMEM_DOMID_RELEASE: {
            /* A domain has gone away - free it and release its domid */
            int ret = 0;

            ret = free_xpmem_domain(ns_state, req_domain);

            if (ret != 0) {
                XPMEM_ERR("Cannot free domain");
            }

            /* Update domid map */
            ret = xpmem_remove_domid(part_state, cmd->domid_req.domid);

            if (ret == 0) {
                XPMEM_ERR("Cannot free domid %lli from hashtable", cmd->domid_req.domid);
            }

            /* No command to send */
            return;
        }
        default: {
            XPMEM_ERR("Unknown domid operation: %s", cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        XPMEM_ERR("Cannot send command on link %lli", link);
    }
}



/* Process a regular XPMEM command. If we get here we are connected to the name
 * server already and have a domid
 */
static void
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
            if (alloc_xpmem_segid(ns_state, req_domain, &(cmd->make.segid))) {
                XPMEM_ERR("Cannot allocate segid");
                out_cmd->make.segid = -1;
            }

            out_cmd->type    = XPMEM_MAKE_COMPLETE;
            out_cmd->dst_dom = cmd->src_dom;
            out_cmd->src_dom = part_state->domid;

            break;

        }

        case XPMEM_REMOVE: {
            /* Free segid to free list */
            if (free_xpmem_segid(ns_state, req_domain, cmd->remove.segid)) {
                XPMEM_ERR("Cannot free segid %lli", cmd->remove.segid);
            }

            out_cmd->type    = XPMEM_REMOVE_COMPLETE;
            out_cmd->dst_dom = cmd->src_dom;
            out_cmd->src_dom = part_state->domid;

            break;

        }

        case XPMEM_GET: {
            struct xpmem_id_val * val = NULL;
            struct xpmem_id_key   key;

            key.segid = cmd->get.segid;

            /* Search segid map */
            val = xpmem_ht_search_id(ns_state, ns_state->segid_map, key);

            if (val == NULL) {
                XPMEM_ERR("Cannot find segid %lli in hashtable. Cannot complete XPMEM_GET", cmd->get.segid);
                goto err_get;
            }

            /* Search domid map for link */
            out_link = xpmem_search_domid(part_state, val->domid);

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
                out_cmd->src_dom  = part_state->domid;
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
            val = xpmem_ht_search_id(ns_state, ns_state->apid_map, key);

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

            /* Search domid map for link */
            out_link = xpmem_search_domid(part_state, val->domid);

            if (out_link == 0) {
                XPMEM_ERR("Cannot find domid %lli in hashtable", val->domid);
                goto err_release;
            }

            out_cmd->dst_dom = val->domid;

            break;

            err_release:
            {
                out_cmd->type    = XPMEM_RELEASE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = part_state->domid;
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
            val = xpmem_ht_search_id(ns_state, ns_state->apid_map, key);

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

            /* Search domid map for link */
            out_link = xpmem_search_domid(part_state, val->domid);

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
                out_cmd->src_dom = part_state->domid;
                out_link         = link;
            }

            break;
        }

        case XPMEM_DETACH: {
            /* Ignore detaches for now */
            {
                out_cmd->type    = XPMEM_DETACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = part_state->domid;
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
            out_link = xpmem_search_domid(part_state, cmd->dst_dom);

            if (out_link == 0) {
                XPMEM_ERR("Cannot find domid %lli in hashtable", cmd->dst_dom);
                return;
            }

            break; 
        }


        default: {
            XPMEM_ERR("Unknown operation: %s", cmd_to_string(cmd->type));
            return;
        }
    }

    /* The nameserver is now the source */
    cmd->src_dom = XPMEM_NS_DOMID;

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        XPMEM_ERR("Cannot send command on link %lli", link);
    }
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
            cmd->req_dom = part_state->domid;
        }

        /* Route to the NS - trivially */
        cmd->src_dom = part_state->domid;
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
        return 0;
    }

    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
            xpmem_ns_process_ping_cmd(part_state, link, cmd);
            break;

        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
        case XPMEM_DOMID_RELEASE:
            xpmem_ns_process_domid_cmd(part_state, req_domain, src_domain, link, cmd);
            break;

        default:
            xpmem_ns_process_xpmem_cmd(part_state, req_domain, src_domain, link, cmd);
            break;
    }   

    return 0;
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
    part_state->domid    = XPMEM_NS_DOMID;
    part_state->ns_state = ns_state;

    /* Populate segid list */
    for (i = XPMEM_MIN_SEGID; i < XPMEM_MAX_UNIQ_ID; i++) {
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

    /* Free segid map */
    free_htable(ns_state->segid_map, 1, 1);

    /* Free apid map */
    free_htable(ns_state->apid_map, 1, 1);

    /* Free any remaining domains */
    free_all_xpmem_domains(ns_state);

    /* Free segid list */
    {
        struct xpmem_segid_list_node * iter, * next;

        list_for_each_entry_safe(iter, next, &(ns_state->segid_free_list), list_node) {
            list_del(&(iter->node);
            kfree(iter);
        }
    }
    
    /* Final cleanup */
    kfree(ns_state);
    part_state->ns_state = NULL;

    printk("XPMEM name service deinitialized\n");

    return 0;
}
