#!/bin/bash

sudo umount /mnt/virtual
sudo rmmod -f minix.ko
make
sudo insmod minix.ko
sudo mount /dev/particao /mnt/virtual

# BRUNO AUGUSTO PEDROSO       12662136
# GIULIANA SALGADO ALEPROTI   12120457
# MATHEUS DE PAULA NICOLAU    12085957
# ROGER OBA                   12048534
