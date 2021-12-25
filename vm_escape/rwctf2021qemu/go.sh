#!/bin/bash
pushd exploit
./build.sh || exit 1
popd

rm -f own_rootfs.cpio
./create_cpio.sh || exit 1

./run.sh