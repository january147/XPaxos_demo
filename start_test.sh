#!/bin/bash
# Date: Sat Jan 11 20:58:55 2020
# Author: January

cat /etc/*-release | grep ubuntu > /dev/null
if [ $? -eq 0 ];then
    gnome-terminal -t "replica1" -- ./replica.py 1 
    gnome-terminal -t "replica2" -- ./replica.py 2
    gnome-terminal -t "replica3" -- ./replica.py 3
fi

cat /etc/*-release | grep deepin > /dev/null
if [ $? -eq 0 ];then
    deepin-terminal -x ./replica.py 1 &
    deepin-terminal -x ./replica.py 2 &
    deepin-terminal -x ./replica.py 3 &
fi
