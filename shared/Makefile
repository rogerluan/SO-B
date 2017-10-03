#
#  Makefile
#  Make file to compile the crypto device module.
#
#  Created on 26/09/17.
#
#  BRUNO AUGUSTO PEDROSO        12662136
#  GIULIANA SALGADO ALEPROTI    12120457
#  MATHEUS DE PAULA NICOLAU     12085957
#  ROGER OBA                    12048534

obj-m += crypto.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc tutorialtest.c -o tutorial

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
