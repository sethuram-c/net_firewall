# External kernel module: Kbuild owns all compiler and linker flags.
ifneq ($(KERNELRELEASE),)
obj-m += kernel/netfw_hello.o
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)
.PHONY: all clean check
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
check:
	bash -n scripts/check_env.sh scripts/test_module.sh
	python3 -m unittest discover -s tests -p 'test_*.py' -v
endif
