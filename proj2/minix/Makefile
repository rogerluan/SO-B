# BRUNO AUGUSTO PEDROSO       12662136
# GIULIANA SALGADO ALEPROTI   12120457
# MATHEUS DE PAULA NICOLAU    12085957
# ROGER OBA                   12048534

#
# Makefile for the Linux minix filesystem routines.
#

obj-$(CONFIG_MINIX_FS) += minix.o

minix-objs := bitmap.o itree_v1.o itree_v2.o namei.o inode.o file.o dir.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
