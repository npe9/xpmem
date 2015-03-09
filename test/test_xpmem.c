#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <xpmem.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

int main(int argc, char ** argv) {
    int * addr;
    int flags, signalable, fd, sec, i;
    xpmem_segid_t segid = 0;
    long num_pages;

    if (argc < 4 || argc > 5) {
        printf("Usage: %s <num_pages> <signalable> <duration (s)> [<well-known segid>]\n", *argv);
        return -1;
    }

    flags = XPMEM_MEM_MODE;
    num_pages = atol(*(++argv));
    signalable = atoi(*(++argv));
    sec = atoi(*(++argv));

    if (argc == 5)
        segid = atoll(*(++argv));

    if (segid > 0)
        flags |= XPMEM_REQUEST_MODE;

    if (signalable)
        flags |= XPMEM_SIG_MODE;

    if (posix_memalign((void **)&addr, PAGE_SIZE, PAGE_SIZE * num_pages) != 0) {
        perror("posix_memalign");
        return -1;
    }

    segid = xpmem_make_hobbes((void *)addr, PAGE_SIZE * num_pages, 
            XPMEM_PERMIT_MODE, (void *)0600,
            flags, segid, &fd);


    printf("segid: %lli\n", segid);

    if (segid <= 0) {
        printf("Cannot allocate segid\n");
        return -1;
    }

    for (i = 0; i < num_pages; i++) {
        void * addr2 = ((void *)addr + (PAGE_SIZE * i));
        *((int *)addr2) = 12340 + i;
        printf("addr: %p, *addr: %d\n",
            addr2, *((int *)addr2));
    }

    if (signalable) {
        struct pollfd fds[1];
        unsigned long irqs;
        int status;

        fds[0].fd = fd;
        fds[0].events = POLLIN | POLLRDNORM;

        printf("Polling fd %d\n", fd);

        status = poll(fds, 1, -1);
        printf("poll status = %d\n", status, irqs);

        status = read(fd, &irqs, sizeof(unsigned long));
        printf("read status = %d, outstanding irqs =%lu\n", status, irqs);

        close(fd);
    }

    if (sec == -1) {
        printf("Sleeping forever\n");
       while (1)
           sleep(1);
    } else {
        for (i = 0; i < sec; i++) {
            printf("Exiting in %d seconds\n", sec - i);
            sleep(1);
        }
    }

    xpmem_remove(segid);

    return 0;
}

