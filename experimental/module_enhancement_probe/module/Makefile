obj-m += sbo_enhancement_probe.o
ccflags-y += -I$(src) -I$(src)/.build -I$(srctree)/drivers/android

ifeq ($(KERNELRELEASE),)
.PHONY: all
all:
	sh ./build.sh
endif
