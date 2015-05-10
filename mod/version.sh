#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <KERN_PATH>"
    exit -1
fi

grep LINUX_VERSION_CODE $1/include/linux/version.h | awk '{print $3}'
