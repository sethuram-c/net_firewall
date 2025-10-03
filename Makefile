# Out-of-tree module: Fedora kernel's Kbuild supplies compiler/linker flags.
ifneq ($(KERNELRELEASE),)
obj-m += kernel/netfw_hello.o
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)
MODULE := kernel/netfw_hello.ko
.PHONY: all clean check info help verify-build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
check:
	bash -n scripts/check_env.sh scripts/test_module.sh scripts/inspect_module.sh
	python3 -m unittest discover -s tests -p 'test_*.py' -v
info:
	@printf 'Running kernel: %s\nKbuild directory: %s\nSource: kernel/netfw_hello.c\n' "$$(uname -r)" '$(KDIR)'
	@test -d "$(KDIR)" || { echo 'ERROR: matching kernel-devel missing; run scripts/check_env.sh' >&2; exit 1; }
verify-build:
	@test -f "$(MODULE)" || { echo 'ERROR: build first with make' >&2; exit 1; }
	@modinfo "$(MODULE)" | grep -E '^(filename|license|description|vermagic):'
help:
	@printf 'make info          show target kernel and Kbuild path\nmake               compile module\nmake verify-build  inspect compiled module metadata\nmake check         run unprivileged checks\nmake clean         remove generated files\n'
endif
