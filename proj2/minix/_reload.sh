#!/bin/bash

sudo umount /mnt/virtual
sudo rmmod -f minix.ko
make
sudo insmod minix.ko
sudo mount /dev/particao /mnt/virtual
