#!/bin/bash

if [ $# -eq 1 ]; then
    DIR=$1
fi

FILE=include/linux/version.h

if [ -e $DIR/$FILE ]; then
    grep LINUX_VERSION_CODE $DIR/$FILE | awk '{print $3}'
else
    grep LINUX_VERSION_CODE /usr/$FILE | awk '{print $3}'
fi
