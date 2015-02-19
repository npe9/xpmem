#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xpmem.h>
#include <client.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    xpmem_apid_t segid, apid;
    long num_pages;
    char * name;

    if (argc != 3) {
        printf("Usage: %s <num_pages> <name>\n", *argv);
        return -1;
    }

    num_pages = atol(*(++argv));
    name = *(++argv);

    if (hobbes_client_init() != 0) {
        printf("Could not init hobbes client\n");
        return -1;
    }

    segid = hobbes_client_get_segid_by_name(name);

    if (segid <= 0) {
        printf("Could not get segid from hobbes db with name %s\n", name);
        return -1;
    }

    printf("segid: %lli\n", segid);
    apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
    printf("apid: %lli\n", apid);

    if (apid <= 0) {
        printf("xpmem get failed\n");
        hobbes_client_deinit();
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
            hobbes_client_deinit();
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

    xpmem_release(apid);

    hobbes_client_deinit();
}
