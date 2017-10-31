#!/bin/bash

sudo rmmod -f minix.ko
make
sudo insmod minix.ko
