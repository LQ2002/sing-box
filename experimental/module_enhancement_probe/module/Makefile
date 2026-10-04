obj-m += sbo_enhancement_probe.o
ccflags-y += -I$(src)

ifeq ($(KERNELRELEASE),)
.PHONY: all
all:
	sh ./build.sh
endif
