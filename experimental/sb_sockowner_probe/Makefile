obj-m += sb_sockowner_probe.o

ifeq ($(KERNELRELEASE),)
.PHONY: all clean
all:
	@test -n "$(KDIR)" || { echo 'Set KDIR to the matching prepared kernel build directory'; exit 1; }
	@test -f "$(KDIR)/Module.symvers" || { echo 'Missing Module.symvers; modules_prepare alone is insufficient'; exit 1; }
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" ARCH=arm64 LLVM=1 modules

clean:
	@test -n "$(KDIR)"
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" ARCH=arm64 LLVM=1 clean
endif
