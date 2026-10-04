obj-m += sbo_enhancement_probe.o
ccflags-y += -I$(src) -I$(srctree)/drivers/android

ifeq ($(KERNELRELEASE),)
.PHONY: all
all:
	sh ./build.sh
endif
