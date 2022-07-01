#!/bin/bash

cd ./kernel_exp/exp
cargo build --target=x86_64-unknown-linux-musl
cd -

sudo mount -t ext4 ./rootfs.img ./mnt
sudo cp ./kernel_exp/exp/target/x86_64-unknown-linux-musl/debug/exp ./mnt/exp
sleep .5
sudo umount ./mnt
