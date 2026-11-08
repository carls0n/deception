# Makefile
obj-m += deception.o
ccflags-y += -w
CFLAGS_REMOVE_deception.o = $(CC_FLAGS_FTRACE)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

