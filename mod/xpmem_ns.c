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
#include <linux/rbtree.h>
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

    /* Domain management */
    struct xpmem_domain          * domain_map[XPMEM_MAX_DOMID];
};


/* List node for name server unique segid accounting */
struct xpmem_segid_list_node {
    unsigned short   uniq;
    struct list_head list_node;
};

/* RB-tree node for domain segid accounting */
struct xpmem_segid_rb_node {
    xpmem_segid_t  segid;
    struct rb_node tree_node;
};

/* RB-tree node for domain apid accounting */
struct xpmem_apid_rb_node {
    xpmem_domid_t  src_domid; /* source domain of the segid */
    xpmem_segid_t  src_segid; /* segid target of the XPMEM_GET */
    xpmem_apid_t   apid;      /* remote apid returned from the XPMEM_GET */
    struct rb_node tree_node;
};

/* Per-domain state */
struct xpmem_domain {
    /* Pointer to ns state */
    struct xpmem_ns_state * state;

    /* Proc directory */
    struct proc_dir_entry * proc_dir;

    /* Assigned domid */
    xpmem_domid_t           domid;

    /* rb-tree of assigned segids */
    struct rb_root          segid_tree;
    /* Number of segids allocated */
    unsigned long           num_segids;

    /* rb-tree of attached apids */
    struct rb_root          apid_tree;
    /* Number of apids attached to */
    unsigned long           num_apids;
};


static void
enclave_segid_show(struct seq_file     * file,
                   struct xpmem_domain * domain)
{
    struct rb_node             * p   = NULL;
    struct xpmem_segid_rb_node * tmp = NULL;

    seq_printf(file, "Domain %lli segids (%lu total):\n", 
        domain->domid, 
        domain->num_segids);

    for (p = rb_first(&(domain->segid_tree)); p != NULL; p = rb_next(p)) {
        tmp = rb_entry(p, struct xpmem_segid_rb_node, tree_node);

        seq_printf(file, "  %lli (tgid = %d, uniq = %u)\n", 
            tmp->segid,
            xpmem_segid_to_tgid(tmp->segid),
            xpmem_segid_to_uniq(tmp->segid));
    }
}

static void
enclave_apid_show(struct seq_file     * file,
                  struct xpmem_domain * domain)
{
    struct rb_node             * p   = NULL;
    struct xpmem_apid_rb_node * tmp = NULL;

    seq_printf(file, "Domain %lli apids (%lu total):\n", 
        domain->domid, 
        domain->num_apids);

    for (p = rb_first(&(domain->apid_tree)); p != NULL; p = rb_next(p)) {
        tmp = rb_entry(p, struct xpmem_apid_rb_node, tree_node);

        seq_printf(file, "  %lli (tgid = %d, uniq = %u), from domid %lli (segid = %lli, tgid = %d, uniq = %u)\n", 
            tmp->apid,
            xpmem_apid_to_tgid(tmp->apid),
            xpmem_apid_to_uniq(tmp->apid),
            tmp->src_domid,
            tmp->src_segid,
            xpmem_segid_to_tgid(tmp->src_segid),
            xpmem_segid_to_uniq(tmp->src_segid));
    }
}

static int
proc_segid_show(struct seq_file * file,
                void            * private_data)
{
    struct xpmem_domain   * domain = (struct xpmem_domain *)file->private;
    struct xpmem_ns_state * state  = NULL;

    if (IS_ERR(domain)) {
        seq_printf(file, "NULL DOMID\n");
        return 0;
    }

    state = domain->state;

    spin_lock(&(state->lock));
    {
        enclave_segid_show(file, domain);
    }
    spin_unlock(&(state->lock));

    return 0;
}

static int
proc_apid_show(struct seq_file * file,
               void            * private_data)
{
    struct xpmem_domain   * domain = (struct xpmem_domain *)file->private;
    struct xpmem_ns_state * state  = NULL;

    if (IS_ERR(domain)) {
        seq_printf(file, "NULL DOMID\n");
        return 0;
    }

    state = domain->state;

    spin_lock(&(state->lock));
    {
        enclave_apid_show(file, domain);
    }
    spin_unlock(&(state->lock));

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


static int
domain_add_xpmem_segid(struct xpmem_domain * domain,
                       xpmem_segid_t         segid)
{
    struct rb_node             ** p      =    &(domain->segid_tree.rb_node);
    struct rb_node              * parent = NULL;
    struct xpmem_segid_rb_node  * tmp    = NULL;

    while (*p) {
        parent = *p;
        tmp    = rb_entry(parent, struct xpmem_segid_rb_node, tree_node);

        if (segid < tmp->segid) {
            p = &(*p)->rb_left;
        } else if (segid > tmp->segid) {
            p = &(*p)->rb_right;
        } else {
            return -1;
        }
    }

    /* Add new node */
    {
        struct xpmem_segid_rb_node * node = kmalloc(sizeof(struct xpmem_segid_rb_node), GFP_KERNEL);

        if (node == NULL) {
            return -1;
        }

        node->segid = segid;

        rb_link_node(&(node->tree_node), parent, p);
        rb_insert_color(&(node->tree_node), &(domain->segid_tree));
    }

    domain->num_segids++;

    return 0;
}

static int
domain_remove_xpmem_segid(struct xpmem_domain * domain,
                          xpmem_segid_t         segid)
{
    struct rb_node             * p   = domain->segid_tree.rb_node;
    struct xpmem_segid_rb_node * tmp = NULL;

    while (p) {
        tmp = rb_entry(p, struct xpmem_segid_rb_node, tree_node);

        if (segid < tmp->segid) {
            p = p->rb_left;
        } else if (segid > tmp->segid) {
            p = p->rb_right;
        } else {
            break;
        }
    }

    if (p) {
        rb_erase(&(tmp->tree_node), &(domain->segid_tree));
        kfree(tmp);

        domain->num_segids--;
        return 0;
    }

    return -1;
}

static int
domain_add_xpmem_apid(struct xpmem_domain * domain, 
                      struct xpmem_domain * segid_domain,
                      xpmem_segid_t         segid,
                      xpmem_apid_t          apid)
{
    struct rb_node             ** p      =    &(domain->apid_tree.rb_node);
    struct rb_node              * parent = NULL;
    struct xpmem_apid_rb_node   * tmp    = NULL;

    while (*p) {
        parent = *p;
        tmp    = rb_entry(parent, struct xpmem_apid_rb_node, tree_node);

        if (apid < tmp->apid) {
            p = &(*p)->rb_left;
        } else if (apid > tmp->apid) {
            p = &(*p)->rb_right;
        } else {
            return -1;
        }
    }

    /* Add new node */
    {
        struct xpmem_apid_rb_node * node = kmalloc(sizeof(struct xpmem_apid_rb_node), GFP_KERNEL);

        if (node == NULL) {
            return -1;
        }

        node->apid       = apid;
        node->src_segid  = segid;
        node->src_domid  = segid_domain->domid;

        rb_link_node(&(node->tree_node), parent, p);
        rb_insert_color(&(node->tree_node), &(domain->apid_tree));
    }

    domain->num_apids++;

    return 0;
}

static int
domain_remove_xpmem_apid(struct xpmem_domain * domain,
                         xpmem_apid_t          apid)
{
    struct rb_node             * p   = domain->apid_tree.rb_node;
    struct xpmem_apid_rb_node * tmp = NULL;

    while (p) {
        tmp = rb_entry(p, struct xpmem_apid_rb_node, tree_node);

        if (apid < tmp->apid) {
            p = p->rb_left;
        } else if (apid > tmp->apid) {
            p = p->rb_right;
        } else {
            break;
        }
    }

    if (p) {
        rb_erase(&(tmp->tree_node), &(domain->apid_tree));
        kfree(tmp);

        domain->num_apids--;
        return 0;
    }

    return -1;
}
                   

static int
alloc_xpmem_segid(struct xpmem_ns_state * ns_state, 
                  struct xpmem_domain   * domain,
                  xpmem_segid_t         * segid)
{
    struct xpmem_segid_list_node * iter  = NULL;
    struct xpmem_id              * id    = NULL;

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

    /* Add to domain */
    if (domain_add_xpmem_segid(domain, *segid) != 0) {
        printk(KERN_ERR "XPMEM: cannot add segid %lli (tgid: %d, uniq: %u) to domain %lli tree\n",
            *segid, 
            xpmem_segid_to_tgid(*segid),
            xpmem_segid_to_uniq(*segid),
            domain->domid);
    }

    return 0;
}

static int
free_xpmem_segid(struct xpmem_ns_state * ns_state,
                 struct xpmem_domain   * domain,
                 xpmem_segid_t           segid)
{
    struct xpmem_segid_list_node * iter = NULL;

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

    /* Remove from domain */
    if (domain_remove_xpmem_segid(domain, segid) != 0) {
        printk(KERN_ERR "XPMEM: cannot remove segid %lli (tgid: %d, uniq: %u) from domain %lli tree\n",
            segid,
            xpmem_segid_to_tgid(segid),
            xpmem_segid_to_uniq(segid),
            domain->domid);
    }

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
        printk(KERN_ERR "XPMEM: out of memory\n");
        return NULL;
    }

    /* Allocate a domain id */
    domain->domid = (xpmem_domid_t)alloc_xpmem_domid(ns_state, domain, domid);

    if (domain->domid == -1) {
        printk(KERN_ERR "XPMEM: No free domids: cannot create new domain!\n");
        return NULL;
    }

    /* Init segid RB tree */
    domain->segid_tree.rb_node = NULL;
    domain->apid_tree.rb_node = NULL;
    domain->num_segids         = 0;
    domain->num_apids         = 0;

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

        apid_entry  = create_proc_entry("apids", 0444, domain->proc_dir);
        if (apid_entry) {
            apid_entry->proc_fops  = &proc_apid_fops;
            apid_entry->data       = domain;
        }
#else
        segid_entry = proc_create_data("segids", 0444, domain->proc_dir, &proc_segid_fops, domain);
        apid_entry  = proc_create_data("apids",  0444, domain->proc_dir, &proc_apid_fops,  domain);
#endif
    }

    /* Save ns state */
    domain->state = ns_state;

    return domain;
}

static int
free_xpmem_domain(struct xpmem_ns_state * ns_state,
                  struct xpmem_domain   * domain)
{
    /* Tear down proc dirs */
    {
        char name[16];

        memset(name, 0, 16);
        snprintf(name, 16, "domid-%d", (int)domain->domid);

        remove_proc_entry("segids", domain->proc_dir);
        remove_proc_entry("apids", domain->proc_dir);
        remove_proc_entry(name, xpmem_proc_dir);
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

/* Hashtable helpers */
static int
xpmem_add_segid(struct xpmem_ns_state * ns_state, 
                xpmem_segid_t           segid,
                xpmem_domid_t           domid)
{
    unsigned long flags  = 0;
    int           status = 0;

    spin_lock_irqsave(&(ns_state->lock), flags);
    {
        status = htable_insert(ns_state->segid_map,
                    (uintptr_t)segid,
                    (uintptr_t)domid);
    }
    spin_unlock_irqrestore(&(ns_state->lock), flags);

    return status;
}

static xpmem_domid_t
xpmem_search_or_remove_segid(struct xpmem_ns_state * ns_state,
                             xpmem_segid_t           segid,
                             int                     remove)
{
    unsigned long flags  = 0;
    xpmem_domid_t result = 0;

    spin_lock_irqsave(&(ns_state->lock), flags);
    {
        if (remove) {
            result = (xpmem_domid_t)htable_remove(ns_state->segid_map,
                        (uintptr_t)segid, 
                        0);
        } else {
            result = (xpmem_domid_t)htable_search(ns_state->segid_map,
                        (uintptr_t)segid); 
        }
    }
    spin_unlock_irqrestore(&(ns_state->lock), flags);

    return result;
}

static xpmem_domid_t
xpmem_search_segid(struct xpmem_ns_state * ns_state,
                   xpmem_segid_t           segid)
{
    return xpmem_search_or_remove_segid(ns_state, segid, 0);
}

static xpmem_domid_t
xpmem_remove_segid(struct xpmem_ns_state * ns_state,
                   xpmem_segid_t           segid)
{
    return xpmem_search_or_remove_segid(ns_state, segid, 1);
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
            printk(KERN_ERR "XPMEM: name server received a PONG?"
                " Are there multiple name servers running?\n");

            return;
        }

        default: {
            printk(KERN_ERR "XPMEM: unknown PING operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
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
                printk(KERN_ERR "XPMEM: cannot create new domain\n");
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            out_cmd->domid_req.domid = domain->domid;

            /* Update domid map */
            ret = xpmem_add_domid(part_state, domain->domid, link);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert domid %lli into hashtable\n", domain->domid);
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

            printk(KERN_ERR "XPMEM: name server has been allocated a domid?"
                " Are there multiple name servers running?\n");

            return;
        }

        case XPMEM_DOMID_RELEASE: {
            /* A domain has gone away - free it and release it's domid */
            int ret = 0;

            ret = free_xpmem_domain(ns_state, req_domain);

            if (ret != 0) {
                printk(KERN_ERR "XPMEM: cannot free domain\n");
            }

            /* Update domid map */
            ret = xpmem_remove_domid(part_state, cmd->domid_req.domid);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot free domid %lli from hashtable\n", cmd->domid_req.domid);
            }

            /* No command to send */
            return;
        }
        default: {
            printk(KERN_ERR "XPMEM: unknown domid operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
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
            int ret = 0;

            /* Allocate a unique segid to this domain */
            if (alloc_xpmem_segid(ns_state, req_domain, &(cmd->make.segid))) {
                printk(KERN_ERR "XPMEM: cannot allocate segid\n");
                out_cmd->make.segid = -1;
                goto out_make;
            }

            /* Add to segid map */
            ret = xpmem_add_segid(ns_state, cmd->make.segid, cmd->src_dom);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert segid %lli hashtable\n", cmd->make.segid);
                out_cmd->make.segid = -1;
                goto out_make;
            }

            out_make: 
            {
                out_cmd->type    = XPMEM_MAKE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = part_state->domid;
            }

            break;

        }

        case XPMEM_REMOVE: {
            xpmem_domid_t domid = 0;

            /* Add segid to free list */
            if (free_xpmem_segid(ns_state, req_domain, cmd->remove.segid)) {
                printk(KERN_ERR "XPMEM: cannot free segid %lli\n", cmd->remove.segid);
            }

            /* Remove segid from map */            
            domid = xpmem_remove_segid(ns_state, cmd->remove.segid); 

            if (domid == 0) {
                printk(KERN_ERR "XPMEM: cannot remove segid %lli from hashtable (tgid: %d, uniq: %d)\n",
                    cmd->remove.segid,
                    xpmem_segid_to_tgid(cmd->remove.segid),
                    xpmem_segid_to_uniq(cmd->remove.segid));
            }

            { 
                out_cmd->type    = XPMEM_REMOVE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = part_state->domid;
            }

            break;

        }

        case XPMEM_GET: {
            xpmem_domid_t domid = 0;

            /* Search segid map */
            domid = xpmem_search_segid(ns_state, cmd->get.segid);

            if (domid == 0) {
                printk(KERN_ERR "XPMEM: cannot find segid %lli in hashtable\n", cmd->get.segid);
                goto err_get;
            }

            /* Search domid map for link */
            out_link = xpmem_search_domid(part_state, domid);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", domid);
                goto err_get;
            }

            out_cmd->dst_dom = domid;

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
            /* Extended apids are always allocated in the range [segid.uniq.
             * segid.uniq + XPMEM_MAX_UNIQ_APID), so we can simply reuse the
             * segid htable by flooring the apid uniq field. Yes, this is a hack
             */
            struct xpmem_id search_id;

            memcpy(&search_id, &(cmd->release.apid), sizeof(struct xpmem_id));
            search_id.uniq &= ~(XPMEM_MAX_UNIQ_APID - 1);

            {
                xpmem_domid_t domid = 0;

                /* Search segid map */
                domid = xpmem_search_segid(ns_state, *((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n", cmd->release.apid);
                    goto err_release;
                }

                /* Search domid map for link */
                out_link = xpmem_search_domid(part_state, domid);

                if (out_link == 0) {
                    printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", domid);
                    goto err_release;
                }

                out_cmd->dst_dom = domid;
            }

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
            /* Extended apids are always allocated in the range [segid.uniq.
             * segid.uniq + XPMEM_MAX_UNIQ_APID), so we can simply reuse the
             * segid htable by flooring the apid uniq field. Yes, this is a hack
             */
            struct xpmem_id search_id;

            memcpy(&search_id, &(cmd->attach.apid), sizeof(struct xpmem_id));
            search_id.uniq &= ~(XPMEM_MAX_UNIQ_APID - 1);

            {
                xpmem_domid_t domid = 0;

                /* Search segid map */
                domid = xpmem_search_segid(ns_state, *((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n", cmd->attach.apid);
                    goto err_attach;
                }

                /* Search domid map for link */
                out_link = xpmem_search_domid(part_state, domid);

                if (out_link == 0) {
                    printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", domid);
                    goto err_attach;
                }

                out_cmd->dst_dom = domid;
            }

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
            /* Ignore detaches for now, because it's not clear how to figure out
             * a destination domain from just a virtual address
             */
            {
                out_cmd->type    = XPMEM_DETACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = part_state->domid;
                out_link         = link;
            }

            break;
        }

        case XPMEM_GET_COMPLETE:  {
            /* Perform apid accounting */

            if (cmd->get.apid > 0) {
                if (domain_add_xpmem_apid(req_domain, src_domain, cmd->get.segid, cmd->get.apid) != 0) {
                    printk(KERN_ERR "XPMEM: cannot add apid %lli to domain %lli tree\n",
                        cmd->get.apid, req_domain->domid);
                }
            }

            goto operation_complete;
        }

        case XPMEM_RELEASE_COMPLETE: {
            /* Perform apid accounting */

            if (domain_remove_xpmem_apid(req_domain, cmd->release.apid) != 0) {
                printk(KERN_ERR "XPMEM: cannot remove apid %lli from domain %lli tree\n",
                    cmd->release.apid, req_domain->domid);
            }

            goto operation_complete;
        }

        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE:
        operation_complete: {

            /* The destination is now the original requesting domain */
            cmd->dst_dom = cmd->req_dom;

            /* Search for the appropriate link */
            out_link = xpmem_search_domid(part_state, cmd->dst_dom);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", cmd->dst_dom);
                return;
            }

            break; 
        }


        default: {
            printk(KERN_ERR "XPMEM: unknown operation: %s\n", cmd_to_string(cmd->type));
            return;
        }
    }

    /* The nameserver is now the source */
    cmd->src_dom = XPMEM_NS_DOMID;

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
    }
}


static void
prepare_domids(struct xpmem_partition_state   * part_state,
               xpmem_link_t                     link,
               struct xpmem_cmd_ex            * cmd)
{
    /* If the source is local, we need to setup the domids for routing - otherwise */
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
        printk(KERN_ERR "XPMEM: Name server processing errant command (dst domid:%lli, ns domid:%lli)\n",
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
                printk(KERN_ERR "XPMEM: Invalid request domid (%lli)\n", r_domid);
                return -1;
            }

            if ((s_domid <= 0) || 
                (s_domid >= XPMEM_MAX_DOMID))
            {
                printk(KERN_ERR "XPMEM: Invalid source domid (%lli)\n", s_domid);
                return -1;
            }

            /* Grab the domains */
            r = part_state->ns_state->domain_map[r_domid];
            s = part_state->ns_state->domain_map[s_domid];

            if (r == NULL) {
                printk(KERN_ERR "XPMEM: NULL request domain (domid:%lli)\n", r_domid);
                return -1;
            }

            if (s == NULL) {
                printk(KERN_ERR "XPMEM: NULL source domain (domid:%lli)\n", s_domid);
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
        printk(KERN_ERR "XPMEM: XPMEM command with malformed domids: (req:%lli, src:%lli, dst:%lli)\n",
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
    ns_state->segid_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!ns_state->segid_map) {
        return -1;
    }

    /* Create everything else */
    spin_lock_init(&(ns_state->lock));
    INIT_LIST_HEAD(&(ns_state->segid_free_list));

    /* Name server partition has a well-known domid */
    part_state->domid    = XPMEM_NS_DOMID;
    part_state->ns_state = ns_state;

    /* Populate segid list */
    for (i = XPMEM_MIN_SEGID; i < XPMEM_MAX_UNIQ_SEGID; i++) {
        iter = kmalloc(sizeof(struct xpmem_segid_list_node), GFP_KERNEL);

        if (!iter) {
            goto err_malloc; 
        }

        iter->uniq = (i * XPMEM_MAX_UNIQ_APID);
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
    free_htable(ns_state->segid_map, 0, 0);

    /* Free any remaining domains */
    free_all_xpmem_domains(ns_state);
    
    /* Final cleanup */
    kfree(ns_state);
    part_state->ns_state = NULL;

    printk("XPMEM name service deinitialized\n");

    return 0;
}
