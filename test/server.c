#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xpmem.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    int * addr;
    int mb;
    int i;
    long size, num_pages;
    xpmem_segid_t segid = 0;

    if (argc != 3) {
        printf("Usage: %s <well-known segid> <memory mb>\n", *argv);
        return -1;
    }

    segid     = atoll(*(++argv));
    mb        = atoi(*(++argv));
    size      = mb * (1024 * 1024);
    num_pages = size / PAGE_SIZE;

    if (posix_memalign((void **)&addr, PAGE_SIZE, num_pages * PAGE_SIZE) != 0) {
        perror("posix_memalign");
        return -1;
    }

//    segid = xpmem_make((void *)addr, num_pages * PAGE_SIZE, XPMEM_REQUEST_MODE, (void *)segid);

    if (segid <= 0) {
        printf("Cannot allocate segid\n");
        return -1;
    }

    for (i = 0; i < num_pages; i++) {
        void * pg = (void *)(addr) + (i * PAGE_SIZE);
        *((int *)pg) = i;

        printf("ar[i] = %d\n", *((int *)pg));
    }

    printf("segid=%lli,MB=%d\n", segid, mb);

    sleep(10000);

    xpmem_remove(segid);

    return 0;
}

