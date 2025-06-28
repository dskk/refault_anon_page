#CFLAGS_REMOVE_refaulter.o += -fpatchable-function-entry
OBJECT_FILES_NON_STANDARD := y
obj-m := refaulter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
