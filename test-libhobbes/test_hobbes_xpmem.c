#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <xpmem.h>
#include <client.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    int * addr;
    int sec, i;
    xpmem_segid_t segid;
    long num_pages;
    char * name;

    if (argc != 4) {
        printf("Usage: %s <num_pages> <duration (s)> <name>\n", *argv);
        return -1;
    }

    num_pages = atol(*(++argv));
    sec = atoi(*(++argv));
    name = *(++argv);

    if (hobbes_client_init() != 0) {
        printf("cannot init hobbes client\n");
        return -1;
    }

    if (posix_memalign((void **)&addr, PAGE_SIZE, PAGE_SIZE * num_pages) != 0) {
        perror("posix_memalign");
        hobbes_client_deinit();
        return -1;
    }

    segid = xpmem_make_hobbes((void *)addr, PAGE_SIZE * num_pages, 
            XPMEM_PERMIT_MODE, (void *)0600,
            XPMEM_MEM_MODE, 0, NULL);

    if (segid <= 0) {
        hobbes_client_deinit();
        printf("Cannot allocate segid\n");
        return -1;
    } 

    for (i = 0; i < num_pages; i++) {
        void * addr2 = ((void *)addr + (PAGE_SIZE * i));
        *((int *)addr2) = 12340 + i;
        printf("addr: %p, *addr: %d\n",
            addr2, *((int *)addr2));
    }

    if (hobbes_client_export_segment(segid, name) != 0) {
        printf("cannot export segment\n");
        return -1;
    }

    printf("Exported segid: %lli, name: %s\n", segid, name);

    for (i = 0; i < sec; i++) {
        printf("exiting in %d seconds\n", sec - i);
        sleep(1);
    }

    if (hobbes_client_remove_segment(segid) != 0)
        printf("cannot remove segment\n");

    xpmem_remove(segid);

    hobbes_client_deinit();

    return 0;
}

