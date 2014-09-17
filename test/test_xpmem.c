#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <xpmem.h>

int main(int argc, char ** argv) {
    xpmem_segid_t   segid = 0;
    int           * var   = NULL;

    if (posix_memalign((void **)&var,  sysconf(_SC_PAGESIZE), sizeof(int)) != 0) {
        perror("posix_memalign");
        return -1;
    }

    *var = 10;

    segid = xpmem_make((void *)var, sysconf(_SC_PAGESIZE), XPMEM_PERMIT_MODE, (void *)0600);

    printf("segid = %lli\n", segid);

    return 0;
}
