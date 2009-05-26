ifeq ($(obj),)
obj		:= .
endif

obj-m		+= tcp_donkan.o
mod-objs	:= tcp_donkan.o
export-objs	:=
list-multi	:=

ifeq ($(KERNELRELEASE),)
KERNELRELEASE	:= $(shell uname -r)
endif


ifeq ($(KERNELPATH),)
KERNELPATH	:= /lib/modules/$(KERNELRELEASE)/build
endif

MODULEPATH	:= $(DESTDIR)/lib/modules/$(KERNELRELEASE)/kernel/net/ipv4

INCS		+= -I$(obj)
EXTRA_CFLAGS	+= $(INCS) $(COPTS)

-include $(TOPDIR)/Rules.make

all:
	$(MAKE) -C $(KERNELPATH) SUBDIRS=$(shell pwd) modules

tcp_donkan.o:
ifneq ($(findstring 2.6,$(KERNELRELEASE)),)
	$(LD) -o tcp_donkan.ko -r $(mod-objs)
endif

install:
	test -d $(MODULEPATH) || mkdir -p $(MODULEPATH)
	install -m 0644 tcp_donkan.ko $(MODULEPATH)
ifeq ($(DESTDIR),)
	/sbin/depmod -ae
endif

clean:
	$(MAKE) -C $(KERNELPATH) SUBDIRS=$(shell pwd) clean
	-rm -f *~ *.symvers
