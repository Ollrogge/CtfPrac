#!/bin/bash
#
./build.sh
./create_cpio.sh
cd ../
./run.sh
cd -
