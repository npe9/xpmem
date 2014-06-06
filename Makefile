#LINUX_KERN=/usr/src/kernels/$(shell uname -r)
LINUX_KERN=/lib/modules/`uname -r`/build/

EXTRA_CFLAGS  += -DMODULE=1 -D__KERNEL__=1

EXTRA_CFLAGS  += -I$(PWD)/include

xpmem-y := 	xpmem_main.o \
		xpmem_make.o \
		xpmem_get.o \
		xpmem_attach.o \
		xpmem_pfn.o \
		xpmem_misc.o \
		xpmem_mmu_notifier.o \
		xpmem_domain.o \
		xpmem_palacios.o \
		xpmem_hashtable.o \
		xpmem_syms.o \
		xpmem_ns.o

xpmem-objs := $(xpmem-y)
obj-m := xpmem.o

all:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) clean

