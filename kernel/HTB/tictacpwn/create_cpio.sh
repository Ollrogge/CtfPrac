pushd cpio_files
find . -print0 | cpio --null -ov --format=newc > ../rootfs.cpio
popd

