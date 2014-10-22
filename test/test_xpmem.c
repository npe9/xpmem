#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <xpmem.h>

int main(int argc, char ** argv) {
    int * addr;
    xpmem_segid_t segid;

    if (posix_memalign((void **)&addr, sysconf(_SC_PAGESIZE), sizeof(int)) != 0) {
        perror("posix_memalign");
        return -1;
    }

    segid = xpmem_make((void *)addr, 4096 * 10, XPMEM_PERMIT_MODE, (void *)0600);
    printf("segid: %lli\n", segid);

    {
        int i = 0;
        for (i = 0; i < 10; i++) {
            void * addr2 = ((void *)addr + (4096 * i));
            *((int *)addr2) = 12340 + i;
            printf("addr: %p, *addr: %d\n",
                addr2, *((int *)addr2));
        }
    }

    while (1) {}

    return 0;
}

