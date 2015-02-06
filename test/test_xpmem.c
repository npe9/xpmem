#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xpmem.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    int * addr;
    xpmem_segid_t segid = 0;
    long num_pages;

    if (argc < 2 || argc > 3) {
        printf("Usage: %s <num_pages> [<well-known segid>]\n", *argv);
        return -1;
    }

    num_pages = atol(*(++argv));

    if (argc == 3) {
        segid = atoll(*(++argv));
    }

    if (posix_memalign((void **)&addr, PAGE_SIZE, PAGE_SIZE * num_pages) != 0) {
        perror("posix_memalign");
        return -1;
    }

    if (segid > 0) {
        segid = xpmem_make((void *)addr, PAGE_SIZE * num_pages, XPMEM_REQUEST_MODE, (void *)segid);
    } else {
        segid = xpmem_make((void *)addr, PAGE_SIZE * num_pages, XPMEM_PERMIT_MODE, (void *)0600);
    }

    printf("segid: %lli\n", segid);

    if (segid <= 0) {
        printf("Cannot allocate segid\n");
        return -1;
    } else {
        int i = 0;

        sleep(5);

        for (i = 0; i < num_pages; i++) {
            void * addr2 = ((void *)addr + (PAGE_SIZE * i));
            *((int *)addr2) = 12340 + i;
            printf("addr: %p, *addr: %d\n",
                addr2, *((int *)addr2));
        }
    }

    sleep(5);
    xpmem_remove(segid);

    return 0;
}

