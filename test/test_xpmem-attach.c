#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <xpmem.h>

#include <unistd.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define DEFAULT_WK_SEGID 1

int main(int argc, char ** argv) {
    xpmem_segid_t segid = DEFAULT_WK_SEGID;
    xpmem_apid_t apid;
    long num_pages;
    int signalable;

    if (argc != 4) {
        printf("Usage: %s <num_pages> <signalable> <segid>\n", *argv);
        return -1;
    }

    num_pages = atol(*(++argv));
    signalable = atoi(*(++argv));
    segid = atoll(*(++argv));

    printf("segid: %lli, num_pages: %lu\n", segid, num_pages);
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
        int data;

        addr.apid = apid;
        addr.offset = 0;

        vaddr = xpmem_attach(addr, PAGE_SIZE * num_pages, NULL);
        if (vaddr == MAP_FAILED) {
            printf("xpmem attach failed\n");
            xpmem_release(apid);
            return -1;
        }

        printf("Attached to vaddr %p\n", vaddr);

        for (i = 0; i < num_pages; i++) {
            vaddr2 = (vaddr + (PAGE_SIZE * i));
            data   = *((int *)vaddr2);

            printf("vaddr2 (%p): %d\n",
                (void * )vaddr2,
                *((int *)vaddr2));

            *((int *)vaddr2) = data + 10; 


        }
        xpmem_detach(vaddr);
    }

    if (signalable) 
        xpmem_signal(apid);


    sleep(10);

    xpmem_release(apid);

    return 0;
}
