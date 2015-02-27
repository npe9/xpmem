LINUX_KERN=/lib/modules/`uname -r`/build/
#LINUX_KERN=../../kernel-source-2.6.32.59

EXTRA_CFLAGS  += -DMODULE=1 -D__KERNEL__=1 -DUSE_DBUG_ON
EXTRA_CFLAGS  += -I$(PWD)/include -I$(PWD)/../include


#
# If the version command doesn't exist it will be built as a top level dependency
#   CRAY_VERSION will then be set on the reinvocation
#

VERSION_CMD=$(PWD)/version
ifneq ($(wildcard $(VERSION_CMD)),)
  CRAY_VERSION=$(shell $(VERSION_CMD))
endif

xpmem-objs := $(xpmem-y)
obj-m := xpmem.o

ifeq ($(CRAY_VERSION),1)
  xpmem-objs  :=  cray/xpmem_main.o \
				cray/xpmem_attach.o \
				cray/xpmem_pfn.o \
				cray/xpmem_misc.o \
				cray/xpmem_mmu_notifier.o
EXTRA_CFLAGS += -DCONFIG_XPMEM_CRAY
else
  xpmem-objs  :=  linux/xpmem_main.o \
				linux/xpmem_attach.o \
				linux/xpmem_pfn.o \
				linux/xpmem_misc.o \
				linux/xpmem_mmu_notifier.o
EXTRA_CFLAGS += -DCONFIG_XPMEM_LINUX
endif

xpmem-y +=  common/xpmem_make.o \
		common/xpmem_get.o \
		common/xpmem_domain.o \
		common/xpmem_partition.o \
		common/xpmem_palacios.o \
		common/xpmem_hashtable.o \
		common/xpmem_syms.o \
		common/xpmem_ns.o \
		common/xpmem_fwd.o \
		common/xpmem_signal.o \
		common/xpmem_irq.o


all: version_exec
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) modules

version_exec: version.c $(VERSION_CMD)
	gcc -I$(LINUX_KERN)/include version.c -o $(VERSION_CMD)

clean:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) clean
	rm -f $(VERSION_CMD)
