#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <xpmem.h>

#include <unistd.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    char * name;
    xpmem_segid_t segid;
    xpmem_apid_t apid;
    long num_pages;

    if (argc != 3) {
        printf("Usage: %s <num_pages> <name>\n", *argv);
        return -1;
    }

    num_pages = atol(*(++argv));
    name = *(++argv);

    printf("name: %s, num_pages: %lu\n", name, num_pages);

    segid = xpmem_search(name, strlen(name));
    if (segid <= 0) {
        printf("Could not find segid for name %s\n", name);
        return -1;
    }
    printf("segid = %lli\n", segid);

    apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
    printf("apid: %lli\n", apid);

    if (apid <= 0) {
        printf("xpmem get failed\n");
        return -1;
    }

    {
        struct xpmem_addr addr;
        void * vaddr, * vaddr2;
        int i;

        addr.apid = apid;
        addr.offset = 0;

        vaddr = xpmem_attach(addr, PAGE_SIZE * num_pages, NULL);
        if (vaddr == MAP_FAILED) {
            printf("xpmem attach failed\n");
            xpmem_release(apid);
            return -1;
        }

        printf("Attached to vaddr %p\n", vaddr);

//       xpmem_detach(vaddr);
//       xpmem_release(apid);

        for (i = 0; i < num_pages; i++) {
            vaddr2 = (vaddr + (PAGE_SIZE * i));
            printf("vaddr2 (%p): %d\n",
                (void * )vaddr2,
                *((int *)vaddr2));
        }

        sleep(3);

        xpmem_detach(vaddr);
        xpmem_release(apid);
    }
}
