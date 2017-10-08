#!/bin/bash

sudo rmmod -f crypto.ko
make
sudo insmod crypto.ko key="1234123412341234"
sudo ./tutorial

