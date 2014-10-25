#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xpmem.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    int * addr;
    char * name = NULL;
    xpmem_segid_t segid;
    int num_pages;

    if (argc < 2 || argc > 3) {
        printf("Usage: %s <num_pages> [<name>]\n", *argv);
        return -1;
    }

    num_pages = atoi(*(++argv));

    if (argc == 3) {
        name = *(++argv);
    }

    if (posix_memalign((void **)&addr, PAGE_SIZE, PAGE_SIZE * num_pages) != 0) {
        perror("posix_memalign");
        return -1;
    }

    if (name) {
        segid = xpmem_make_name((void *)addr, PAGE_SIZE * num_pages, XPMEM_PERMIT_MODE, (void *)0600, name, strlen(name));
    } else {
        segid = xpmem_make((void *)addr, PAGE_SIZE * num_pages, XPMEM_PERMIT_MODE, (void *)0600);
    }

    printf("segid: %lli\n", segid);

    {
        int i = 0;
        for (i = 0; i < num_pages; i++) {
            void * addr2 = ((void *)addr + (PAGE_SIZE * i));
            *((int *)addr2) = 12340 + i;
            printf("addr: %p, *addr: %d\n",
                addr2, *((int *)addr2));
        }
    }

    while (1) {}

    return 0;
}

