LINUX_KERN=/lib/modules/`uname -r`/build/
#LINUX_KERN=../../kernel-source-2.6.32.59

EXTRA_CFLAGS  += -DMODULE=1 -D__KERNEL__=1 -DUSE_DBUG_ON
EXTRA_CFLAGS  += -I$(PWD)/include -I$(PWD)/../include

# Get the Linux kernel version number
VERSION=$(shell $(PWD)/version.sh $(PWD)/$(LINUX_KERN))

define KERN_VERSION
${shell echo "$(1)*(2^16) + $(2)*(2^8) + $(3)" | bc}
endef

xpmem-objs := $(xpmem-y)
obj-m := xpmem.o


# Old Cray version is 2.6.32.59
ifeq ($(VERSION),$(call KERN_VERSION,2,6,32))
  xpmem-objs  :=  cray-2.6.32.59/xpmem_main.o \
				cray-2.6.32.59/xpmem_pfn.o \
				cray-2.6.32.59/xpmem_misc.o \
				cray-2.6.32.59/xpmem_mmu_notifier.o \
				cray-2.6.32.59/xpmem_syms.o
EXTRA_CFLAGS += -DCONFIG_XPMEM_OLD_CRAY
else 
  xpmem-objs  :=  linux/xpmem_main.o \
			linux/xpmem_pfn.o \
			linux/xpmem_misc.o \
			linux/xpmem_mmu_notifier.o \
			linux/xpmem_syms.o
EXTRA_CFLAGS += -DCONFIG_XPMEM_LINUX
endif

# Linux internalized do_mmap in 3.4.0, which changes the attach code
# significantly
do-mmap=$(shell [[ $(VERSION) -le $(call KERN_VERSION,3,4,0) ]] && echo 1 || echo 0 )
ifeq ($(do-mmap), 1)
	xpmem-objs += common/xpmem_attach-dommap.o
else
	xpmem-objs += common/xpmem_attach-vmmmap.o
endif

xpmem-y +=  common/xpmem_make.o \
		common/xpmem_get.o \
		common/xpmem_domain.o \
		common/xpmem_partition.o \
		common/xpmem_palacios.o \
		common/xpmem_hashtable.o \
		common/xpmem_ns.o \
		common/xpmem_fwd.o \
		common/xpmem_signal.o \
		common/xpmem_irq.o

all:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) clean
