obj-m += sbo_identity.o
ccflags-y += -I$(src) -I$(src)/.build

ifeq ($(KERNELRELEASE),)
.PHONY: all
all:
	sh ./build.sh
endif
