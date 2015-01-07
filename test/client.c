#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <xpmem.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

unsigned long get_tick(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_usec + (tv.tv_sec * (1000 * 1000));
}

int main(int argc, char ** argv) {
    int * addr;
    int mb, i, iters, mode, ar_size;
    long size, num_pages;
    int * ar;
    unsigned long at_start, at_end, end;

    xpmem_segid_t segid = 0;
    xpmem_apid_t  apid  = 0;

    if (argc != 5) {
        printf("Usage: %s <well-known segid> <memory mb> <iterations> <r/w/n>\n", *argv);
        return -1;
    }

    segid     = atoll(*(++argv));
    mb        = atoi(*(++argv));
    iters     = atoi(*(++argv));
    mode      = atoi(*(++argv));

    size      = mb * (1024 * 1024);
    num_pages = size / PAGE_SIZE;

    /* Allocate ar for memory reads */
    ar = malloc(num_pages * PAGE_SIZE);
    if (ar == NULL) {
        perror("malloc");
        return -1;
    }

    apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
    if (apid <= 0) {
        printf("xpmem get failed\n");
        return -1;
    }

    for (i = 0; i < iters; i++) {
        struct xpmem_addr addr;
        void * vaddr;
        int j;

        addr.apid   = apid;
        addr.offset = 0;

        at_start = get_tick();

        vaddr = xpmem_attach(addr, PAGE_SIZE * num_pages, NULL);
        if (vaddr == MAP_FAILED) {
            printf("xpmem attach failed\n");
            xpmem_release(apid);
            return -1;
        }

        at_end = get_tick();

        switch (mode) {
            case 0:
                /* Read */
                for (j = 0; j < num_pages; j++) {
                    void * pg = vaddr + (j * PAGE_SIZE);
                    ar[j] = *((int *)pg);

    //                printf("ar[i] = %d\n", ar[i]);
                }
                break;
            case 1:
                /* Write */
                for (j = 0; j < num_pages; j++) {
                    void * pg = vaddr + (j * PAGE_SIZE);
                    *((int *)pg) = j;

    //                printf("ar[i] = %d\n", *((int *)pg));
                }
                break;
            default:
                break;
        }

        end = get_tick();

        xpmem_detach(vaddr);

        printf("%lu %lu\n", 
            at_end - at_start,
            end    - at_start);
    }

    xpmem_release(apid);

    return 0;
}

