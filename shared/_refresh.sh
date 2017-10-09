#!/bin/sh
echo "Refreshing the module..."
sudo rmmod crypto.ko -f
make
sudo insmod crypto.ko key="1234567890123456"
echo "Done!"
echo "Executing the program now..."
sudo ./tutorial
