obj-m += sbo_identity_bridge.o
ccflags-y += -I$(src) -I$(src)/.build/generated

ifeq ($(KERNELRELEASE),)
.PHONY: all
all:
	sh ./build.sh
endif
