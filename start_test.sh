#!/bin/bash
# Date: Sat Jan 11 20:58:55 2020
# Author: January

gnome-terminal -t "replica1" -- ./replica.py 1 
gnome-terminal -t "replica2" -- ./replica.py 2

